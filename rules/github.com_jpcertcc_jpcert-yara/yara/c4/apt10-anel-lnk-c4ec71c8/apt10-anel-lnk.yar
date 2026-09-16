rule APT10_ANEL_lnk {
    meta:
	description = "Link malware ANEL downloader"
        author = "JPCERT/CC Incident Response Group"
        hash = "1986ccf4d33b8dc291e7cbe73194a3e4cb617e37277ab93b7e320b6ea716f59d"

    strings:
        $s1 = "$($env:APPDATA)+'\\Microsoft\\Templates\\'" ascii wide
        $s2 = ".Length - 1)]);expand $" ascii wide
        $s3 = "Invoke-Item -Path $docPath;Remove-Item -Path $cabPath -Force" ascii wide
        $cab_sig = {4D 53 43 46 00 00 00 00} 

    condition:
        (uint32(0) == 0x0000004C) and
        3 of them
}