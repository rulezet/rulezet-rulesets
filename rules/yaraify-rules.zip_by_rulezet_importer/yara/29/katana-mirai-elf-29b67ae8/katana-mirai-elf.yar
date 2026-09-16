rule Katana_Mirai_ELF {
    meta:
        description = "Katana Mirai variant (DDoS bot with rootkit)"
        author = "Nokia Deepfield ERT"
        date = "2026-03-15"
        family = "Katana"
        hash = "aaaa8948c27d3e89f4e7fba810d0784bb4fa81a0ea44a75e3a7d226ad22c9b69"
        yarahub_uuid = "a4f2c8e1-7b35-4d92-ae6f-91c4d3e08f52"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "8437d2f80f1ab1eb2fcbc044741893ae"

    strings:
        $mirai_id = "/bin/busybox MIRAI"
        $banner = "god will save us all"
        $greeting = "meow"
        $ipc_hb = "/data/local/tmp/.bot_hb"
        $ipc_ipc = "/data/local/tmp/.bot_ipc"
        $ipc_err = "/data/local/tmp/.bot_errors"
        $domain_path = "/var/.domains"
        $dns_cache = "/tmp/.dns_cache"
        $rootkit_ctl = "wlan_helper"
        $tcc_path = "/data/local/tmp/tcc"
        $com_update = "com.system.update"
        $citizenfx = "CitizenFX"
        $putty = "SSH-2.0-PuTTY_Release_0.8"
        $systemdd = "systemdd-worker"

    condition:
        uint32(0) == 0x464c457f and
        (
            ($mirai_id and ($banner or $greeting)) or
            (2 of ($ipc_hb, $ipc_ipc, $ipc_err)) or
            ($rootkit_ctl and $tcc_path) or
            ($com_update and $citizenfx and $putty) or
            ($systemdd and any of ($ipc_*)) or
            ($domain_path and $dns_cache)
        )
}