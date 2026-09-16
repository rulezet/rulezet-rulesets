rule CecBot_APK
{
    meta:
        author = "Nokia Deepfield ERT"
        description = "CecBot DDoS botnet - Android APK with libattack.so + libwatchdog.so"
        date = "2026-03-26"
        family = "CecBot"
        hash = "b3c1d5fc273d19556b09f935b9b09b782b113b98a8a010ebcbb5de5bfce77e67"
        yarahub_uuid = "4caa9e2a-e791-4e00-a663-2af185a29598"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "e750c27b9a4fcaa6a048d86c4d011c92"

    strings:
                $lib_attack_arm = "lib/armeabi-v7a/libattack.so"
        $lib_attack_arm64 = "lib/arm64-v8a/libattack.so"
        $lib_watchdog_arm = "lib/armeabi-v7a/libwatchdog.so"
        $lib_watchdog_arm64 = "lib/arm64-v8a/libwatchdog.so"

                        $xor_key = { 73 a5 1c e7 4b 92 d8 3f }

    condition:
        uint16(0) == 0x4b50 and          filesize < 500KB and
        (
                        (1 of ($lib_attack_*) and 1 of ($lib_watchdog_*)) or

                        ($xor_key and 1 of ($lib_attack_*))
        )
}