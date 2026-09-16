rule CN_Honker_portRecall_bc {
    meta:
        description = "Script from disclosed CN Honker Pentest Toolset - file bc.pl"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "Disclosed CN Honker Pentest Toolset"
        date = "2015-06-23"
		score = 70
        hash = "2084990406398afd856b2309c7f579d7d61c3767"
        id = "ea74f260-87e6-5027-b558-628949cae32a"
    strings:
        $s0 = "print \"[*] Connected to remote host \\n\"; " fullword ascii 
        $s1 = "print \"Usage: $0 [Host] [Port] \\n\\n\";  " fullword ascii 
        $s5 = "print \"[*] Resolving HostName\\n\"; " fullword ascii 
    condition:
        filesize < 10KB and all of them
}