rule OLE_LNK_InternetExplorer_IDLIST_Suspicious
{
    meta:
        author = "node5"
        description = "Detects OLE-embedded LNK with Internet Explorer IDLIST containing suspicious WebDAV/UNC/file:// strings within item boundaries"
        date = "2026-02-06"
        yarahub_author_twitter = "@node5"
        yarahub_reference_md5 = "83ebe0e9d69abebc6fe33e47d27df885"
        yarahub_uuid = "ae8b195a-0b28-4018-a6c9-e51045247ef9"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    strings:
                $ole_magic = { D0 CF 11 E0 A1 B1 1A E1 }

                $lnk_header = { 4C 00 00 00 01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46 }

                $ie_guid = { 80 53 1C 87 A0 42 69 10 A2 EA 08 00 2B 30 30 9D }

                $davwwwroot = "DavWWWRoot" ascii wide nocase
        $ssl = "@SSL" ascii wide nocase
        $webdav = "webdav" ascii wide nocase
        $file_proto = "file://" ascii wide nocase
                $port_80 = "@80/" ascii wide
        $port_443 = "@443/" ascii wide
        $port_8443 = "@8443/" ascii wide
        $port_ssl = "@SSL@" ascii wide

                $cdn_pages = "pages.dev" ascii wide nocase
        $cdn_workers = "workers.dev" ascii wide nocase
        $cdn_bunny = "b-cdn.net" ascii wide nocase

                                $path_unc_a = { 5C 5C ?? }          $path_fwd_a = { 2F 2F ?? }          $path_mix_a = { 5C 2F ?? }  
                $path_unc3_a = { 5C 5C 5C }          $path_fwd3_a = { 2F 2F 2F }          $path_mix2_a = { 5C 2F 2F }          $path_mix3_a = { 5C 5C 2F }          $path_mix4_a = { 5C 2F 5C 2F }  
                $path_unc_w = { 5C 00 5C 00 ?? 00 }          $path_fwd_w = { 2F 00 2F 00 ?? 00 }          $path_mix_w = { 5C 00 2F 00 ?? 00 }  
                $path_unc3_w = { 5C 00 5C 00 5C 00 }          $path_fwd3_w = { 2F 00 2F 00 2F 00 }          $path_mix2_w = { 5C 00 2F 00 2F 00 }          $path_mix3_w = { 5C 00 5C 00 2F 00 }          $path_mix4_w = { 5C 00 2F 00 5C 00 2F 00 }  
                $exe = ".exe" ascii wide nocase
        $dll = ".dll" ascii wide nocase
        $scr = ".scr" ascii wide nocase
        $bat = ".bat" ascii wide nocase
        $cmd = ".cmd" ascii wide nocase
        $ps1 = ".ps1" ascii wide nocase
        $vbs = ".vbs" ascii wide nocase
        $vbe = ".vbe" ascii wide nocase
        $js = ".js" ascii wide nocase
        $jse = ".jse" ascii wide nocase
        $wsf = ".wsf" ascii wide nocase
        $wsh = ".wsh" ascii wide nocase
        $hta = ".hta" ascii wide nocase
        $lnk = ".lnk" ascii wide nocase
        $application = ".application" ascii wide nocase
        $msi = ".msi" ascii wide nocase
        $msp = ".msp" ascii wide nocase
        $cpl = ".cpl" ascii wide nocase
        $jar = ".jar" ascii wide nocase
        $pif = ".pif" ascii wide nocase
        $gadget = ".gadget" ascii wide nocase
        $reg = ".reg" ascii wide nocase

    condition:
                $ole_magic at 0 and
        filesize < 50MB and
        filesize > 512 and

                for any i in (1..#lnk_header) : (
                        (@lnk_header[i] >= 0) and

                        (uint32(@lnk_header[i]+0x14) & 0x00000001) != 0 and

                        uint16(@lnk_header[i]+0x4C) > 0 and
            uint16(@lnk_header[i]+0x4C) < 4096 and
            @lnk_header[i]+0x4C+uint16(@lnk_header[i]+0x4C)+2 < filesize and

                                                                                                                        (
                                for any j in (1..#ie_guid) : (
                                        @ie_guid[j] >= @lnk_header[i]+0x4E and
                    @ie_guid[j] < @lnk_header[i]+0x4E+uint16(@lnk_header[i]+0x4C) and

                                                            @ie_guid[j] >= @lnk_header[i]+0x4E+4 and
                    uint8(@ie_guid[j]-2) == 0x1F and

                                                                                                    uint16(@ie_guid[j]-4) > 0 and
                    uint16(@ie_guid[j]-4) <= 512 and
                    @ie_guid[j]-4+uint16(@ie_guid[j]-4) < @lnk_header[i]+0x4E+uint16(@lnk_header[i]+0x4C) and

                                        uint16(@ie_guid[j]-4+uint16(@ie_guid[j]-4)) > 0 and
                    uint16(@ie_guid[j]-4+uint16(@ie_guid[j]-4)) <= 512 and
                    @ie_guid[j]-4+uint16(@ie_guid[j]-4)+uint16(@ie_guid[j]-4+uint16(@ie_guid[j]-4)) <= @lnk_header[i]+0x4E+uint16(@lnk_header[i]+0x4C) and

                                        (
                                                for any of ($path_unc_a, $path_fwd_a, $path_mix_a, $path_unc3_a, $path_fwd3_a, $path_mix2_a, $path_mix3_a, $path_mix4_a) : (
                            $ at (@ie_guid[j]-4+uint16(@ie_guid[j]-4)+3)
                        )
                        or
                        for any of ($path_unc_w, $path_fwd_w, $path_mix_w, $path_unc3_w, $path_fwd3_w, $path_mix2_w, $path_mix3_w, $path_mix4_w) : (
                            $ at (@ie_guid[j]-4+uint16(@ie_guid[j]-4)+3)
                        )
                        or
                                                for any of ($davwwwroot, $ssl, $webdav, $file_proto, $port_80, $port_443, $port_8443, $port_ssl, $cdn_pages, $cdn_workers, $cdn_bunny, $exe, $dll, $scr, $bat, $cmd, $ps1, $vbs, $vbe, $js, $jse, $wsf, $wsh, $hta, $lnk, $application, $msi, $msp, $cpl, $jar, $pif, $gadget, $reg) : (
                            $ in (@ie_guid[j]-4+uint16(@ie_guid[j]-4)+2 .. @ie_guid[j]-4+uint16(@ie_guid[j]-4)+uint16(@ie_guid[j]-4+uint16(@ie_guid[j]-4)))
                        )
                    )
                )
            )
        )
}