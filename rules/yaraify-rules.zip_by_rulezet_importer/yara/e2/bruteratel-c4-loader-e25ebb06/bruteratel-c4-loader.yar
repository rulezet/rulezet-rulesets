rule BruteRatel_C4_Loader
{
    meta:
        id = "o7gUPtSyc4rx18q1QyJnUT"
        fingerprint = "da569ef9491c348880081c879c1d8b8c8a7e5d96dfdacc7937ce89945a1ee26b"
        version = "1.0"
        date = "2026-03-31"
        modified = "2026-03-31"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "HTTPS://GITHUB.COM/KIRKDERP/YARA"
        author = "kirkderp"
        description = "Brute Ratel C4 stager/loader -- direct syscalls, multiple injection techniques, PPID spoofing"
        category = "MALWARE"
        malware = "BRUTERATEL"
        mitre_att = "T1055.012"

        reference = "https://github.com/kirkderp/yara"
        triage_score = 10
        triage_description = "Brute Ratel C4 loader with process injection detected."
        yarahub_uuid = "e4cd2b4f-1f41-4d71-9ecc-b4ee2ab4c422"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "def6f8062367490a92ad6650522da0cf"

    strings:
                $marker = "dnSUXRIL" ascii wide

                $sec_sysc = "_sysc" ascii
                $sec_retplne = ".retplne" ascii

                $inj_earlybird = "Early Bird APC Queue" wide
        $inj_kcb = "KernelCallbackTable" wide
        $inj_threadhijack = "Thread Hijacking" wide
        $inj_sectionview = "Section View Mapping" wide
        $inj_settimer = "Executing shellcode via SetTimer" wide
        $inj_fls = "Executing shellcode via FLS Callback" wide
        $inj_geoid = "Executing shellcode via EnumSystemGeoID" wide
        $inj_linedda = "Executing shellcode via LineDDA" wide
        $inj_clipboard = "Executing shellcode via Clipboard" wide

                $ppid_spoof = "Spoofed parent process" wide

                $apc_queued = "APC queued" wide

                $payload_decrypt = "Payload decrypted" wide

    condition:
        uint16(0) == 0x5A4D
        and filesize > 100KB and filesize < 2MB
        and (
                        $marker and ($sec_sysc or $sec_retplne)
            or (
                                $marker and 2 of ($inj_earlybird, $inj_kcb, $inj_threadhijack, $inj_sectionview, $inj_settimer, $inj_fls, $inj_geoid, $inj_linedda, $inj_clipboard)
            )
            or (
                                ($sec_sysc and $sec_retplne)
                and $ppid_spoof
                and ($apc_queued or $payload_decrypt)
                and 3 of ($inj_earlybird, $inj_kcb, $inj_threadhijack, $inj_sectionview, $inj_settimer, $inj_fls, $inj_geoid, $inj_linedda, $inj_clipboard)
            )
        )
}