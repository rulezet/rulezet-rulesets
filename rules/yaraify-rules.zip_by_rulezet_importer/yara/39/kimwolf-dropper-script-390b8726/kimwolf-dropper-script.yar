rule kimwolf_dropper_script
{
    meta:
        author = "Nokia Deepfield ERT"
        description = "Kimwolf residential proxy botnet - ADB sideload install script"
        date = "2026-03-09"
        family = "kimwolf"
        severity = "high"
        yarahub_uuid = "8e8a791e-6de9-4983-85ce-3d2a97fa63b8"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "09587b0c67d0c9e7211c8b2edb6037ba"

    strings:
                $shell1 = "#!/bin/sh"
        $shell2 = "#!/bin/bash"
        $shell3 = "#!/system/bin/sh"

                $adb_bypass = "verifier_verify_adb_installs"

                $pm_install = "pm install"

                $am_start = "am startservice"
        $am_start2 = "am start-foreground-service"

                $dl_toybox = "toybox nc"
        $dl_busybox = "busybox nc"

                $pkg_androidsvc = "com.a.androidsvc"
        $pkg_logcatd = "com.android.logcatd"
        $pkg_networkservice = "com.example.networkservice"
        $pkg_proxypeer = "com.proxypeer.peerapp"
        $pkg_abcproxy = "com.abcproxy.proxysdk"
        $pkg_n2 = "com.n2.systemservice06"

                $svc_sdk = "SDKService"

                $doze_bypass = "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS"
        $doze_bypass2 = "dumpsys deviceidle whitelist"

                $ip_dropper1 = "89.39.70.40"
        $ip_dropper2 = "95.133.240.218"
        $ip_dropper3 = "89.125.255.206"
        $ip_dropper4 = "130.12.180.126"

    condition:
        filesize < 10KB and
        not uint32(0) == 0x464c457f and          not uint32(0) == 0x04034b50 and          1 of ($shell*) and          (
                        ($adb_bypass and $pm_install and 1 of ($pkg_*)) or

                        (1 of ($dl_*) and $pm_install and ($am_start or $am_start2) and $svc_sdk) or

                        (1 of ($ip_dropper*) and $pm_install and 1 of ($pkg_*)) or

                        ($adb_bypass and 1 of ($dl_*) and ($am_start or $am_start2)) or

                        (1 of ($pkg_*) and ($doze_bypass or $doze_bypass2) and $svc_sdk)
        )
}