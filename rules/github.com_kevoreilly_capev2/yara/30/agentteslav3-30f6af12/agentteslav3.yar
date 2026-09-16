rule AgentTeslaV3 {
    meta:
        author = "ditekshen"
        description = "AgentTeslaV3 infostealer payload"
        cape_type = "AgentTesla payload"
    strings:
                $s_specific1 = "get_kbok" fullword ascii
        $s_specific2 = "get_CHoo" fullword ascii
        $s_specific3 = "KillTorProcess" fullword ascii
        $s_specific4 = "GetMozilla" ascii
        $s_specific5 = "torbrowser" wide
        $s_specific6 = "bot%telegramapi%" wide
        $s_specific7 = "%chatid%" wide
        
                $s_typo      = "set_Lenght" fullword ascii

                $m1 = "yyyy-MM-dd hh-mm-ssCookieapplication/zipSCSC_.jpegScreenshotimage/jpeg/log.tmpKLKL_.html<html></html>Logtext/html[]Time" ascii
        $m2 = "%image/jpg:Zone.Identifier\\tmpG.tmp%urlkey%-f \\Data\\Tor\\torrcp=%PostURL%127.0.0.1POST+%2B" ascii
        $m3 = ">{CTRL}</font>Windows RDPcredentialpolicyblobrdgchrome{{{0}}}CopyToComputeHashsha512CopySystemDrive\\WScript.ShellRegReadg401" ascii
        $m4 = "%startupfolder%\\%insfolder%\\%insname%/\\%insfolder%\\Software\\Microsoft\\Windows\\CurrentVersion\\Run%insregname%SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\RunTruehttp" ascii
        $m5 = "\\WindowsLoad%ftphost%/%ftpuser%%ftppassword%STORLengthWriteCloseGetBytesOpera" ascii

                        $s_generic1 = "set_UseShellExecute" fullword ascii
        $s_generic2 = "set_IsBodyHtml" fullword ascii
        $s_generic3 = "set_AllowAutoRedirect" fullword ascii
        $s_generic4 = "set_RedirectStandardOutput" fullword ascii

    condition:
        (
                        2 of ($m*)
        ) or (
            uint16(0) == 0x5a4d and
            (
                                5 of ($s_specific*) or
                
                                ($s_typo and 4 of ($s_generic*))
            )
        )
}