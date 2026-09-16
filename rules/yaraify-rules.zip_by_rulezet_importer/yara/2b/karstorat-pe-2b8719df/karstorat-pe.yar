rule KarstoRAT_PE
{
    meta:
        id = "aZQQAm3QfB2IR1UHD3PBUZ"
        fingerprint = "a4b3255cd18172a5b82a4e8d91c9f5786ce828ba7f6429e62eebef15941637c9"
        version = "1.0"
        date = "2026-03-10"
        modified = "2026-03-10"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "HTTPS://GITHUB.COM/KIRKDERP/YARA"
        author = "derp.ca"
        description = "KarstoRAT native C++ RAT - all builds (author hibby, MSVC x64)"
        category = "MALWARE"
        malware = "KARSTORAT"
        malware_type = "RAT"
        mitre_att = "T1219"
        reference = "https://github.com/kirkderp/yara"
        triage_score = 10
        triage_description = "KarstoRAT remote access trojan detected."
        yarahub_uuid = "26e4ba2c-6c62-4f65-a606-48a7eda59aa4"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "a5bef919eb260af5bb8eba243ed4fd75"

    strings:
                $pdb = "\\Users\\hibby\\Desktop\\Project1\\" ascii

                $ua = "SecurityNotifier" ascii wide

                $c2_heartbeat = "/notify?event=heartbeat&user=" ascii
                $c2_log = "/notify?event=log&user=" ascii

                $ep_screen = "/upload-screen" ascii
        $ep_keylog = "/upload-keylog" ascii
        $ep_sysinfo = "/upload-sysinfo" ascii
        $ep_shell = "/upload-shell-output" ascii
        $ep_webcam = "/upload-webcam" ascii
        $ep_download = "/client-download?user=" ascii

                $cmd_screenshot = "SCREENSHOT" ascii wide
        $cmd_keylog_on = "KEYLOG_ON" ascii wide
        $cmd_keylog_off = "KEYLOG_OFF" ascii wide
        $cmd_shell_start = "SHELL_START" ascii wide
        $cmd_shell_input = "SHELL_INPUT:" ascii wide
        $cmd_sysinfo = "SYSINFO" ascii wide
        $cmd_webcam = "WEBCAM" ascii wide
        $cmd_rotate_on = "ROTATE_ON" ascii wide
        $cmd_mouse_swap = "MOUSE_SWAP" ascii wide
        $cmd_wallpaper = "WALLPAPER:" ascii wide
        $cmd_startup_on = "STARTUP_ON" ascii wide
        $cmd_folder_on = "FOLDER_ON" ascii wide
        $cmd_task_on = "TASK_ON" ascii wide

                $persist_svc = "SecurityService" ascii wide
        $persist_task = "schtasks /create /f /sc onlogon /tn \"SystemCheck\" /tr \"" ascii

                $action_fmt = "Action: [" ascii

                $json_cpu = "\"cpu\":\"" ascii
        $json_ram = "\"ram_total_gb\":" ascii
        $json_disk = "\"disk_total_gb\":" ascii
        $json_procs = "\"processes\":[" ascii

    condition:
        uint16(0) == 0x5A4D
        and filesize > 50KB and filesize < 500KB
        and (
                        ($pdb and $ua)
            or
                        ($ua and $c2_heartbeat and $c2_log and 2 of ($ep_*))
            or
                        (8 of ($cmd_*) and $action_fmt and ($persist_svc or $persist_task))
            or
                        (3 of ($json_*) and ($c2_heartbeat or $c2_log) and $ua)
        )
}