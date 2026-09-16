rule Txt_Sql {
    meta:
        description = "Chinese Hacktool Set - Webshells - file Sql.txt"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "f7813f1dfa4eec9a90886c80b88aa38e2adc25d5"
        id = "586f23d4-3a04-520d-b75b-f9bbcf67ceeb"
    strings:
        $s1 = "cmd=chr(34)&\"cmd.exe /c \"&request.form(\"cmd\")&\" > 8617.tmp\"&chr(34)" fullword ascii
        $s2 = "strQuery=\"dbcc addextendedproc ('xp_regwrite','xpstar.dll')\"" fullword ascii
        $s3 = "strQuery = \"exec master.dbo.xp_cmdshell '\" & request.form(\"cmd\") & \"'\" " fullword ascii
        $s4 = "session(\"login\")=\"\"" fullword ascii
    condition:
        filesize < 15KB and all of them
}