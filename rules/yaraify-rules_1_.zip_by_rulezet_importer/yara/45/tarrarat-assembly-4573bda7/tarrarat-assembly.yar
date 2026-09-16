rule tarrarat_assembly
{
    meta:
        yarahub_uuid = "144f59a0-d984-4bf8-b038-9bc181b1a7a5"
        yarahub_license = "CC0 1.0"
        yarahub_author_twitter = "@Lenny_3BO"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "a44fd5e62ca073c5b45d782cdb4624ee"
        author      = "Lenny-3BO"
        description = "TarraRAT (RSquare) .NET RAT client -- assembly + config indicators"
        family      = "win.tarrarat"
        version     = "1.0"
        date        = "2026-04-30"
        reference   = "hunts/omegatech-as202412-tun1-sweep"

    strings:
                $mutex_prefix   = "RSQ_" ascii wide

                $port_str       = "4782" ascii wide

                $aes_class      = "Aes256" ascii wide

                $msgpack        = "MessageSerializer" ascii wide

                $ns_root        = "TarraRAT." ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 20MB and
        $mutex_prefix and
        2 of ($port_str, $aes_class, $msgpack, $ns_root)
}