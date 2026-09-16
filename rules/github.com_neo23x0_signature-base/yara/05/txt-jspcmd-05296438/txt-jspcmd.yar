rule Txt_jspcmd {
    meta:
        description = "Chinese Hacktool Set - Webshells - file jspcmd.txt"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "1d4e789031b15adde89a4628afc759859e53e353"
        id = "53eb6caf-3578-5df7-a1d8-9e4038b6f57e"
    strings:
        $s0 = "if(\"1752393\".equals(request.getParameter(\"Confpwd\"))){" fullword ascii
        $s4 = "out.print(\"Hi,Man 2015\");" fullword ascii
    condition:
        filesize < 1KB and 1 of them
}