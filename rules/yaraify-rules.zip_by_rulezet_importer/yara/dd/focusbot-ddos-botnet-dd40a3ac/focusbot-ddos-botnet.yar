rule focusbot_ddos_botnet
{
    meta:
        author = "Nokia Deepfield ERT"
        description = "FocusBot DDoS botnet - plaintext HTTP C2 with UDP/TCP flood attacks"
        date = "2026-03-09"
        family = "focusbot"
        severity = "high"
        yarahub_uuid = "56c97c07-b9db-4994-9f0a-818710f0b3de"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "55bee9f1addc6f616ad99334039b8774"

    strings:
                $api_heartbeat = "/api/bot_heartbeat"
        $api_command = "/api/get_command"
        $ua_focusbot = "FocusBot/"

                $bot_id_fmt = "FOCUS_%04X%04X_%s"
        $bot_id_file = ".focus_bot_id"

                $heartbeat_json = "bot_id\":\"%s\",\"os\":\"%s\",\"cpu\":%d"

                $method_fivem = "FIVEM"
        $method_ovh = "OVH" fullword

                $status_attacking = "ATTACKING"
        $status_alive = "ALIVE" fullword

                $masq_telnetd = "/usr/sbin/telnetd"

                $os_linux_iot = "Linux/IoT"

                $dns_amp = { 00 01 01 00 00 01 00 00 00 00 00 01 06 67 6f 6f 67 6c 65 03 63 6f 6d 00 00 ff 00 01 }

    condition:
        uint32(0) == 0x464c457f and
        (
                        (1 of ($api_*) and $bot_id_fmt) or

                        ($heartbeat_json and $ua_focusbot) or

                        ($bot_id_file and 1 of ($api_*) and 1 of ($status_*)) or

                        ($ua_focusbot and $os_linux_iot and $masq_telnetd) or

                        (3 of ($method_*, $status_*, $os_linux_iot, $masq_telnetd) and $bot_id_file) or

                        ($dns_amp and $bot_id_file)
        )
}