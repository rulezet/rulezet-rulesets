rule PAExec_Cloaked {
   meta:
      description = "Detects a renamed remote access tool PAEXec (like PsExec)"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://researchcenter.paloaltonetworks.com/2017/03/unit42-shamoon-2-delivering-disttrack/"
      date = "2017-03-27"
      score = 70
      hash1 = "01a461ad68d11b5b5096f45eb54df9ba62c5af413fa9eb544eacb598373a26bc"
      id = "fad8417b-bbdb-5a4e-8324-660e27cb39f8"
   strings:
      $x1 = "Ex: -rlo C:\\Temp\\PAExec.log" fullword ascii
      $x2 = "Can't enumProcesses - Failed to get token for Local System." fullword wide
      $x3 = "PAExec %s - Execute Programs Remotely" fullword wide
      $x4 = "\\\\%s\\pipe\\PAExecIn%s%u" fullword wide
      $x5 = "\\\\.\\pipe\\PAExecIn%s%u" fullword wide
      $x6 = "%%SystemRoot%%\\%s.exe" fullword wide
      $x7 = "in replacement for PsExec, so the command-line usage is identical, with " fullword ascii
      $x8 = "\\\\%s\\ADMIN$\\PAExec_Move%u.dat" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and 1 of ($x*) )
      and not filename == "paexec.exe"
      and not filename == "PAExec.exe"
      and not filename == "PAEXEC.EXE"
      and not filename matches /Install/
      and not filename matches /uninstall/
}