use bitdemon::domain::result_slice::ResultSlice;
use bitdemon::domain::title::Title;
use bitdemon::lobby::storage::{
    FileVisibility, PublisherStorageService, StorageFileInfo, StorageServiceError,
};
use bitdemon::networking::bd_session::BdSession;
use log::{info, warn};
use num_traits::ToPrimitive;
use std::fs;
use std::fs::DirEntry;
use std::path::{Component, PathBuf};
use std::str::FromStr;
use std::time::UNIX_EPOCH;

/// Map a locale-specific publisher filename to its English equivalent.
///
/// A French EUR console asks for `online_tu9_mp_french.wad` and
/// `fr_ffotd_tu9_mp_148.ff.00`. The store only carries the English builds, and a
/// missing `.wad` leaves the online menu with nothing to populate its playlists
/// from - so "Black Ops II online" does nothing. The English `.wad` drives
/// matchmaking identically for every locale, so serve it as the fallback.
fn delocalise(filename: &str) -> Option<String> {
    const LANGS: &[&str] = &[
        "french", "german", "italian", "spanish", "portuguese", "brazilian",
        "polish", "russian", "japanese", "dutch", "korean",
    ];
    for lang in LANGS {
        let needle = format!("_{lang}");
        if filename.contains(needle.as_str()) {
            return Some(filename.replace(needle.as_str(), "_english"));
        }
    }
    const PREFIXES: &[&str] = &["fr_", "de_", "it_", "es_", "pt_", "nl_", "pl_", "ru_", "ja_", "ko_"];
    for pfx in PREFIXES {
        if let Some(rest) = filename.strip_prefix(*pfx) {
            return Some(format!("en_{rest}"));
        }
    }
    None
}

pub struct DwPublisherStorageService {}

impl PublisherStorageService for DwPublisherStorageService {
    fn get_publisher_file_data(
        &self,
        session: &BdSession,
        filename: String,
    ) -> Result<Vec<u8>, StorageServiceError> {
        info!("Requesting publisher file {}", filename.as_str());

        let path_buf = PathBuf::from_str(&filename)
            .map_err(|_| StorageServiceError::StorageFileNotFoundError)?;

        let directory_traversal = path_buf
            .components()
            .any(|component| component == Component::ParentDir);

        if directory_traversal {
            warn!("User attempted directory traversal!",);
            return Err(StorageServiceError::StorageFileNotFoundError);
        }

        let full_file_path = format!(
            "storage/publisher/{}/{filename}",
            session.authentication().unwrap().title.to_u32().unwrap()
        );

        if let Ok(data) = fs::read(&full_file_path) {
            return Ok(data);
        }

        if let Some(alt_name) = delocalise(&filename) {
            let alt_path = format!(
                "storage/publisher/{}/{alt_name}",
                session.authentication().unwrap().title.to_u32().unwrap()
            );
            if let Ok(data) = fs::read(&alt_path) {
                info!("Served {alt_name} in place of {filename}");
                return Ok(data);
            }
        }

        warn!("Requested publisher file could not be found");
        Err(StorageServiceError::StorageFileNotFoundError)
    }

    fn list_publisher_files(
        &self,
        session: &BdSession,
        min_date_time: i64,
        item_offset: usize,
        item_count: usize,
    ) -> Result<ResultSlice<StorageFileInfo>, StorageServiceError> {
        info!(
            "Listing publisher files min_date_time={min_date_time} item_offset={item_offset} item_count={item_count}"
        );

        let title = session.authentication().unwrap().title;
        let full_dir_path = format!("storage/publisher/{}", title.to_u32().unwrap());

        let dir = fs::read_dir(full_dir_path);
        if dir.is_err() {
            return Ok(ResultSlice::new(Vec::new(), item_offset));
        }

        let file_info: Vec<StorageFileInfo> = dir
            .unwrap()
            .filter(|entry| entry.is_ok())
            .skip(item_offset)
            .map(|entry| entry.unwrap())
            .map(|entry| Self::map_info_info(title, entry))
            .filter(|info| info.created >= min_date_time)
            .take(item_count)
            .collect();

        if !file_info.is_empty() {
            Ok(ResultSlice::new(file_info, item_offset))
        } else {
            Err(StorageServiceError::StorageFileNotFoundError)
        }
    }

    fn filter_publisher_files(
        &self,
        session: &BdSession,
        min_date_time: i64,
        item_offset: usize,
        item_count: usize,
        filter: String,
    ) -> Result<ResultSlice<StorageFileInfo>, StorageServiceError> {
        info!(
            "Filtering publisher files min_date_time={min_date_time} item_offset={item_offset} item_count={item_count} filter={filter}"
        );

        let title = session.authentication().unwrap().title;
        let full_dir_path = format!("storage/publisher/{}", title.to_u32().unwrap());

        let dir = fs::read_dir(full_dir_path);
        if dir.is_err() {
            return Ok(ResultSlice::new(Vec::new(), item_offset));
        }

        // A French console filters for `online_tu9_mp_french.wad`; only the
        // English build is on disk. Match either the requested prefix or its
        // English form so the listing is non-empty and the console then
        // downloads the file that actually exists.
        let alt_filter = delocalise(&filter);
        let file_info: Vec<StorageFileInfo> = dir
            .unwrap()
            .filter(|entry| entry.is_ok())
            .filter(|entry| {
                let name = entry.as_ref().unwrap().file_name();
                let name = name.to_str().unwrap();
                name.starts_with(&filter)
                    || alt_filter.as_deref().is_some_and(|a| name.starts_with(a))
            })
            .skip(item_offset)
            .map(|entry| entry.unwrap())
            .map(|entry| Self::map_info_info(title, entry))
            .filter(|info| info.created >= min_date_time)
            .take(item_count)
            .collect();

        if !file_info.is_empty() {
            Ok(ResultSlice::new(file_info, item_offset))
        } else {
            Err(StorageServiceError::StorageFileNotFoundError)
        }
    }
}

impl DwPublisherStorageService {
    pub fn new() -> DwPublisherStorageService {
        DwPublisherStorageService {}
    }

    fn map_info_info(title: Title, entry: DirEntry) -> StorageFileInfo {
        let metadata = entry.metadata().unwrap();
        StorageFileInfo {
            id: 0,
            filename: entry.file_name().into_string().unwrap(),
            title,
            file_size: metadata.len(),
            created: metadata
                .created()
                .unwrap()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            modified: metadata
                .modified()
                .unwrap()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            visibility: FileVisibility::VisiblePublic,
            owner_id: 0,
        }
    }
}
