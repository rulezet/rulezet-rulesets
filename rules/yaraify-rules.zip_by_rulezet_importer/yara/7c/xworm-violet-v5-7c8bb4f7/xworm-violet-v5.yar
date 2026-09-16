rule XWorm_Violet_v5
{
    meta:
        id = "7AXQEJIq4084eHO9b1OQcK"
        fingerprint = "6d279e229932392323fef344c12c921620e5e7db573d3b3b1f00861ff55e2e1b"
        version = "1.0"
        date = "2026-03-31"
        modified = "2026-03-31"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "HTTPS://GITHUB.COM/KIRKDERP/YARA"
        author = "kirkderp"
        description = "XWorm / Violet v5 -- 80+ command RAT with HVNC, keylogger, crypto clipper, USB worm, webcam capture"
        category = "MALWARE"
        malware = "XWORM"
        mitre_att = "T1219"

        reference = "https://github.com/kirkderp/yara"
        triage_score = 10
        triage_description = "XWorm Violet v5 RAT detected."
        yarahub_uuid = "74ba7289-0235-4623-bae1-1a96abe95c18"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "403f1a3b591c6da42efd290ec3094cdd"

    strings:
                        $drop_name = "WinSc32" ascii wide

                        $cleanup_b64 = "V2luVGVtcENsZWFuMzIuYmF0" ascii wide

                $webcam_api = "capCreateCaptureWindowA" ascii

                $hvnc_api = "OpenInputDesktop" ascii

                $version_b64 = "VmlvbGV0IHY1" ascii wide

                $sep_b64 = "WFNYU1hTWA" ascii wide

                $mutex_b64 = "SE9IRTZTOEZhWlpsR2YwZg" ascii wide

                        $show_update_b64 = "U2hvd1VwZGF0ZVNjcmVlbg" ascii wide
                $hide_update_b64 = "SGlkZVVwZGF0ZVNjcmVlbg" ascii wide

                        $guid_b64 = "M2Q4NDdjNWMtNGY1YS00OTE4LTllMDctYTk2Y2VhNDkwNDhk" ascii wide

    condition:
        uint16(0) == 0x5A4D
        and filesize > 30KB and filesize < 500KB
        and (
                        $guid_b64
            or (
                                $version_b64 and $sep_b64
            )
            or (
                                ($drop_name or $cleanup_b64)
                and ($webcam_api or $hvnc_api)
                and 2 of ($show_update_b64, $hide_update_b64, $mutex_b64, $sep_b64)
            )
        )
}