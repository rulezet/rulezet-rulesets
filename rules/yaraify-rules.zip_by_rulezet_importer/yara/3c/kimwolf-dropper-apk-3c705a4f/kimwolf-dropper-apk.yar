rule kimwolf_dropper_apk
{
    meta:
        author = "Nokia Deepfield ERT"
        description = "Kimwolf residential proxy botnet - Android APK dropper"
        date = "2026-03-09"
        family = "kimwolf"
        severity = "high"
        yarahub_uuid = "8788f651-5f65-4c0f-a192-dc16c77a4cd6"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "09587b0c67d0c9e7211c8b2edb6037ba"

    strings:
                $lib_device = "libdevice.so"
        $lib_device1 = "libdevice1.so"
        $lib_device_emu = "libdevice_emu.so"
        $lib_android_rt = "libandroid_runtime.so"
        $lib_dalvik_rt = "libdalvik_runtime.so"
        $lib_bcsdk = "libbcsdk.so"

                $asset_task = "assets/device_task"

                $classes_dex = "classes.dex"
        $manifest = "AndroidManifest.xml"

                $pkg_proxysdk = { 63 00 6f 00 6d 00 2e 00 61 00 62 00 63 00 70 00
                          72 00 6f 00 78 00 79 00 2e 00 70 00 72 00 6f 00
                          78 00 79 00 73 00 64 00 6b 00 }          $pkg_lolsdk   = { 63 00 6f 00 6d 00 2e 00 61 00 62 00 63 00 70 00
                          72 00 6f 00 78 00 79 00 2e 00 6c 00 6f 00 6c 00
                          73 00 64 00 6b 00 }          $pkg_logcatd  = { 63 00 6f 00 6d 00 2e 00 61 00 6e 00 64 00 72 00
                          6f 00 69 00 64 00 2e 00 6c 00 6f 00 67 00 63 00
                          61 00 74 00 64 00 }          $pkg_androidsvc = { 63 00 6f 00 6d 00 2e 00 61 00 2e 00 61 00 6e 00
                            64 00 72 00 6f 00 69 00 64 00 73 00 76 00 63 00 }          $pkg_netservice = { 63 00 6f 00 6d 00 2e 00 65 00 78 00 61 00 6d 00
                            70 00 6c 00 65 00 2e 00 6e 00 65 00 74 00 77 00
                            6f 00 72 00 6b 00 73 00 65 00 72 00 76 00 69 00
                            63 00 65 00 }          $pkg_n2       = { 63 00 6f 00 6d 00 2e 00 6e 00 32 00 2e 00 73 00
                          79 00 73 00 74 00 65 00 6d 00 73 00 65 00 72 00
                          76 00 69 00 63 00 65 00 30 00 36 00 }          $pkg_proxypeer = { 63 00 6f 00 6d 00 2e 00 70 00 72 00 6f 00 78 00
                           79 00 70 00 65 00 65 00 72 00 2e 00 70 00 65 00
                           65 00 72 00 61 00 70 00 70 00 }  
                $path_sylvia = "SylviaFennec/AbcProxySDK"

                $byteconnect = "byteconnect.io"

    condition:
        uint32(0) == 0x04034b50 and          $classes_dex and $manifest and          (
                        ($lib_android_rt and $lib_dalvik_rt) or

                        (1 of ($pkg_*) and 1 of ($lib_*)) or

                        ($lib_device and $lib_bcsdk) or

                        $lib_device_emu or

                        $path_sylvia or

                        $asset_task or

                        ($lib_device and $lib_device1) or

                        ($lib_device and $byteconnect) or

                        (2 of ($pkg_*))
        )
}