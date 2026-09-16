rule tarrarat_c2_panel
{
    meta:
        yarahub_uuid = "04d07d39-ac5d-4191-8ef0-f5cde04ef5d6"
        yarahub_license = "CC0 1.0"
        yarahub_author_twitter = "@Lenny_3BO"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "a44fd5e62ca073c5b45d782cdb4624ee"
        author      = "Lenny-3BO"
        description = "TarraRAT C2 operator panel -- BankNotifierWindow class + WPF source/PE shape"
        family      = "win.tarrarat"
        version     = "2.0"
        date        = "2026-05-01"
        reference   = "hunts/flashakacoder-tarrarat-cluster"

    strings:
                $bank_notifier  = "BankNotifierWindow" ascii wide

                $tarrarat       = "TarraRAT" ascii wide

                $cs_using       = "using System" ascii
        $cs_namespace   = "namespace " ascii

                $wpf_pe         = "PresentationFramework" ascii wide

                $license_url    = "178.16.54.149" ascii wide
        $api_path       = "/api/validate" ascii wide
        $panel_title    = "TarraRAT C2" ascii wide

    condition:
        filesize < 100MB and
        $bank_notifier and
        $tarrarat and
        (
                        ($cs_using and $cs_namespace)
            or
                        (uint16(0) == 0x5A4D and $wpf_pe)
            or
                        2 of ($license_url, $api_path, $panel_title)
        )
}