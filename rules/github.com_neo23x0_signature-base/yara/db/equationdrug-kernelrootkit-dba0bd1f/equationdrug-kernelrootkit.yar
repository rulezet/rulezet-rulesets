rule EquationDrug_KernelRootkit {
   meta:
      description = "EquationDrug - Kernel mode stage 0 and rootkit (Windows 2000 and above) - msndsrv.sys"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
      date = "2015/03/11"
      modified = "2023-01-06"
      hash = "597715224249e9fb77dc733b2e4d507f0cc41af6"
      id = "92491e30-4041-5c8b-8e4e-7bc2b1d3234b"
   strings:
      $s0 = "Microsoft(R) Windows (TM) Operating System" fullword wide
      $s1 = "Parmsndsrv.dbg" fullword ascii
      $s2 = "\\Registry\\User\\CurrentUser\\" wide
      $s3 = "msndsrv.sys" fullword wide
      $s5 = "\\REGISTRY\\MACHINE\\System\\CurrentControlSet\\Control\\Windows" wide
      $s6 = "\\Device\\%ws_%ws" wide
      $s7 = "\\DosDevices\\%ws" wide
      $s9 = "\\Device\\%ws" wide
   condition:
      all of them
}