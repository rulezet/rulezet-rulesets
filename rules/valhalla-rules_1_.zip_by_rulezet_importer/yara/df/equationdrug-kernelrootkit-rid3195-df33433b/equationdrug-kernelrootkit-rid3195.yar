rule EquationDrug_KernelRootkit_RID3195 : APT DEMO T1014 T1543_003 {
   meta:
      description = "EquationDrug - Kernel mode stage 0 and rootkit (Windows 2000 and above) - msndsrv.sys"
      author = "Florian Roth"
      reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
      date = "2015-03-11 13:28:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-01-06"
      tags = "APT, DEMO, T1014, T1543_003"
      minimum_yara = "3.5.0"
      
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