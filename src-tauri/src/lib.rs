mod network_check;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            network_check::run_get_ai_ok_check,
            network_check::list_check_history,
            network_check::delete_check_history,
            network_check::clear_check_history
        ])
        .run(tauri::generate_context!())
        .expect("error while running get ai ok");
}
