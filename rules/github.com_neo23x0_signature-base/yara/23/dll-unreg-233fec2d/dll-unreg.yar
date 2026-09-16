rule dll_UnReg {
    meta:
        description = "Chinese Hacktool Set - file UnReg.bat"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "d5e24ba86781c332d0c99dea62f42b14e893d17e"
        id = "5c14486d-72a2-5a18-9db0-ce0ab61fdce7"
    strings:
        $s0 = "regsvr32.exe /u C:\\windows\\system32\\PacketX.dll" fullword ascii 
        $s1 = "del /F /Q C:\\windows\\system32\\PacketX.dll" fullword ascii 
    condition:
        filesize < 1KB and 1 of them
}