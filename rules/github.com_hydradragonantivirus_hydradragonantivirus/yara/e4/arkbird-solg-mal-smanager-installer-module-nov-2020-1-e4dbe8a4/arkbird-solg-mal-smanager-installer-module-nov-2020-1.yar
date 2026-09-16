rule ARKBIRD_SOLG_Mal_Smanager_Installer_Module_Nov_2020_1: FILE {
  meta:
    description = "Detect installer module of Smanager (November 2020)"
    author      = "Arkbird_SOLG"
    id          = "364285bc-2173-5ff0-85d2-af06051a3b70"
    date        = "2020-12-19"
    modified    = "2020-12-19"
    reference   = "https://insight-jp.nttsecurity.com/post/102glv5/pandas-new-arsenal-part-3-smanager"
    source_url  = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-12-19/Mal_Smanager_Installer_Module_Nov_2020_1.yar#L1-L24"
    license_url = "N/A"
    logic_hash  = "380d28f6cdea24f807f3c29207eb0b8888ebdfea215c53df164fe080c3917438"
    score       = 75
    quality     = 61
    tags        = "FILE"
    hash1       = "97a5fe1d2174e9d34cee8c1d6751bf01f99d8f40b1ae0bce205b8f2f0483225c"

  strings:
    $s1  = "cmd /c schtasks /F /create /tn:Windows\\Update /tr \"%s\"   /sc HOURLY"
    $s2  = "%s\\system32\\svchost.exe -k %s"
    $s3  = "%systemroot%"
    $s4  = { 25 55 53 45 52 50 52 4f 46 49 4c 45 25 5c [1-8] 5c [1-8] 2e 63 61 62 }
    $s5  = "Smanager_ssl.dll"
    $s6  = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost"
    $s7  = "SYSTEM\\CurrentControlSet\\Services\\"
    $s8  = "C:\\windows\\apppatch\\"
    $s9  = "TmV0QmlvcyBNZXNzYWdlciBSZWdpc3Rlcg==" fullword ascii
    $s10 = { 68 74 74 70 73 3d 25 5b 5e 3a 5d 3a 25 64 00 00 68 74 74 70 73 3d 00 00 73 6f 63 6b 73 3d 25 5b 5e 3a 5d 3a 25 64 00 00 73 6f 63 6b 73 3d 00 00 68 74 74 70 3d 25 5b 5e 3a 5d 3a 25 64 00 00 00 68 74 74 70 3d }
    $s11 = "&About VVSup..." fullword wide
    $s12 = "%d.tmp" fullword ascii

  condition:
    uint16(0) == 0x5a4d and filesize > 90KB and 7 of them
}