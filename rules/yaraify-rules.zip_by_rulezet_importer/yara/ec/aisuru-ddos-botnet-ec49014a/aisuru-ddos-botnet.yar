rule aisuru_ddos_botnet
{
    meta:
        author = "Nokia Deepfield ERT"
        description = "Aisuru DDoS botnet - Mirai derivative with custom crypto"
        date = "2026-03-09"
        reference = "https://blog.xlab.qianxin.com/aisuru-botnet-en/"
        family = "aisuru"
        aka = "airashi"
        severity = "high"
        yarahub_uuid = "d5bef5fd-e68e-4d67-ab79-7c198615229c"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "279c1addab1dfaf8a1d7dc9fe3875b81"

    strings:
                        $crypto_key = { de ad be ef ca fe ba be 12 34 56 78 90 ab cd ef }

                $xor_key_early = { 12 34 56 78 90 ab cd ef fe dc ba 98 76 54 32 10 }

                $magic_deadbeef_1337 = { ef be ad de 37 13 20 04 }          $magic_1ceb = { da 00 eb 1c }                               $magic_1ceb_verify = { a4 88 eb 1c }                
                        $table_key = "PJbiNbbeasddDfsc"

                $jackskid_frsh = "FrshPckBnnnSplit"
        $jackskid_botd = "botd_single_lock"

                $conn_check = "motherfuckingwebsite.com"

                $chacha20 = "expand 32-byte k"
                $chacha20_scrambled = "nd 3expa2-byte k"
                        $chacha20_truncated = "expand 3te k"

                $cafebabe_le = { be ba fe ca }

                $ssh_motty = "SSH-2.0-MoTTY_Release_0.77"
        $ssh_tectia = "SSH-2.0-Tectia_6.4.13"
        $ssh_libssh = "SSH-2.0-libssh-0.8.0"
        $ssh_putty = "SSH-2.0-PuTTY_Release_0.78"
        $ssh_win81 = "SSH-2.0-OpenSSH_for_Windows_8.1"

                $vse_query = "TSource Engine Query"

                $atk_wra = "attacks_wra"
        $atk_stomp = "attacks_stomp"
        $atk_raknet = "attacks_raknet"
        $atk_tfo = "attacks_tfo"
        $atk_vse = "attacks_vse"
        $atk_gre = "attacks_gre"
        $atk_ack = "attacks_ack"
        $atk_std = "attacks_std"
        $atk_socket = "attacks_socket"

                $fn_toggle_obf = "toggle_obf"
        $fn_select_profile = "select_profile"
        $fn_send_heartbeat = "send_heartbeat"
        $fn_single_instance = "single_instance"
        $fn_esi_fd = "esi_fd"

                $locker_init = "locker_init"
        $locker_find = "locker_find"
        $locker_insert = "locker_insert"
        $locker_pid = "locker_pid"

                $ua_gcore = "GCore Labs Cyberthreat Research"

                $dns_dvrexpert = "dvrexpert"
        $dns_tiananmen = "tiananmensquare1989"
        $dns_krebstresser = "krebstresser"
        $dns_idsource = "idsource"

    condition:
        uint32(0) == 0x464c457f and                                          not ($jackskid_frsh and not $magic_1ceb and not $cafebabe_le) and
        not ($jackskid_botd and not $magic_1ceb and not $cafebabe_le and not $table_key) and
        (
                        $crypto_key or
            $xor_key_early or

                        ($magic_1ceb and $magic_1ceb_verify) or

                        ($magic_deadbeef_1337 and ($table_key or $conn_check)) or

                        ($conn_check and 3 of ($atk_*)) or

                        (3 of ($ssh_*) and $vse_query and $conn_check) or

                        (2 of ($locker_*) and 2 of ($fn_*)) or

                                    ($table_key and ($chacha20 or $chacha20_scrambled or $chacha20_truncated)) or

                        ($table_key and $cafebabe_le) or

                        ($table_key and 1 of ($dns_*)) or

                        (5 of ($atk_*) and 2 of ($fn_*)) or

                        ($ua_gcore and 2 of ($atk_*)) or

                        (3 of ($ssh_*) and $fn_send_heartbeat and $fn_toggle_obf)
        )
}