rule EquationDrug_NetworkSniffer5 {
   meta:
      description = "EquationDrug - Network-sniffer/patcher - atmdkdrv.sys"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
      date = "2015/03/11"
      modified = "2023-01-06"
      hash = "09399b9bd600d4516db37307a457bc55eedcbd17"
      id = "9eac2c51-3ad7-5346-a985-39733bc204c2"
   strings:
      $s0 = "Microsoft(R) Windows (TM) Operating System" fullword wide
      $s1 = "\\Registry\\User\\CurrentUser\\" wide
      $s2 = "atmdkdrv.sys" fullword wide
      $s4 = "\\Device\\%ws_%ws" wide
      $s5 = "\\DosDevices\\%ws" wide
      $s6 = "\\Device\\%ws" wide
   condition:
      all of them
}