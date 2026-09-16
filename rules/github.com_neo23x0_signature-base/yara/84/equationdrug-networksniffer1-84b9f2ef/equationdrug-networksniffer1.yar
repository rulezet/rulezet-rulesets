rule EquationDrug_NetworkSniffer1 {
   meta:
      description = "EquationDrug - Backdoor driven by network sniffer - mstcp32.sys, fat32.sys"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
      date = "2015/03/11"
      modified = "2023-01-06"
      hash = "26e787997a338d8111d96c9a4c103cf8ff0201ce"
      id = "21a500e7-3011-50e6-b685-f4f65d6dee17"
   strings:
      $s0 = "Microsoft(R) Windows (TM) Operating System" fullword wide
      $s1 = "\\Registry\\User\\CurrentUser\\" wide
      $s3 = "sys\\mstcp32.dbg" fullword ascii
      $s7 = "mstcp32.sys" fullword wide
      $s8 = "p32.sys" fullword ascii
      $s9 = "\\Device\\%ws_%ws" wide
      $s10 = "\\DosDevices\\%ws" wide
      $s11 = "\\Device\\%ws" wide
   condition:
      all of them
}