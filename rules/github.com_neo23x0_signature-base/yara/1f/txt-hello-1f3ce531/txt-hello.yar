rule Txt_hello {
    meta:
        description = "Chinese Hacktool Set - Webshells - file hello.txt"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "697a9ebcea6a22a16ce1a51437fcb4e1a1d7f079"
        id = "42d01411-e333-543d-84a2-758c13bad2df"
    strings:
        $s0 = "Dim myProcessStartInfo As New ProcessStartInfo(\"cmd.exe\")" fullword ascii
        $s1 = "myProcessStartInfo.Arguments=\"/c \" & Cmd.text" fullword ascii
        $s2 = "myProcess.Start()" fullword ascii
        $s3 = "<p align=\"center\"><a href=\"?action=cmd\" target=\"_blank\">" fullword ascii
    condition:
        filesize < 25KB and all of them
}