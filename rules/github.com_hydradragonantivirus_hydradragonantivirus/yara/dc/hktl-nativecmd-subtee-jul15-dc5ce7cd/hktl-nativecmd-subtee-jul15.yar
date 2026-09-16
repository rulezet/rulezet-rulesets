rule HKTL_NativeCmd_subTee_Jul15 {
  meta:
    description   = "NativeCmd - used by various threat groups"
    author        = "Florian Roth (Nextron Systems)"
    reference     = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
    date          = "2015-07-10"
    modified      = "2023-01-06"
    old_rule_name = "subTee_nativecmd"
    score         = 40
    hash          = "758e6b519f6c0931ff93542b767524fc1eab589feb5cfc3854c77842f9785c92"

  strings:
    $x2  = "RunFile: couldn't find ShellExecuteExA/W in SHELL32.DLL!" fullword ascii
    $x3  = "Error executing CreateProcess()!!" fullword wide
    $x4  = "cmdcmdline" fullword wide
    $x5  = "Invalid input handle!!!" fullword ascii
    $s5  = "Usage: destination [reference]" fullword wide
    $s6  = ".com;.exe;.bat;.cmd" wide
    $s15 = "%-8s %-3s  %*s %s  %s" fullword wide
    $s16 = " %%%c in (%s) do " fullword wide

  condition:
    uint16(0) == 0x5a4d and (2 of ($x*) or 6 of ($s*))
}