rule CN_Tools_srss {
    meta:
        description = "Chinese Hacktool Set - file srss.bat"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "092ab0797947692a247fe80b100fb4df0f9c37a0"
        id = "13191e2e-fbcd-5e0b-af55-cc10f2583c1b"
    strings:
        $s0 = "srss.exe -idx 0 -ip"
        $s1 = "-port 21 -logfilter \"_USER ,_P" ascii 
    condition:
        filesize < 100 and all of them
}