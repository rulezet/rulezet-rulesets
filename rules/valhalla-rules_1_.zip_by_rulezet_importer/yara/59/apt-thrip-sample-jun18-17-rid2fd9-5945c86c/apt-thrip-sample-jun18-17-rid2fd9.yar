rule APT_Thrip_Sample_Jun18_17_RID2FD9 : APT DEMO EXE FILE G0030 G0076 {
   meta:
      description = "Detects sample found in Thrip report by Symantec "
      author = "Florian Roth"
      reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
      date = "2018-06-21 12:14:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "05036de73c695f59adf818d3c669c48ce8626139d463b8a7e869d8155e5c0d85"
      hash2 = "08d8c610e1ec4a02364cb53ba44e3ca5d46e8a177a0ecd50a1ef7b5db252701d"
      hash3 = "14535607d9a7853f13e8bf63b629e3a19246ed9db6b4d2de2ca85ec7a7bee140"
      tags = "APT, DEMO, EXE, FILE, G0030, G0076"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "c:\\users\\administrator\\desktop\\code\\skeyman2\\" ascii
      $x2 = "\\SkeyMan2.pdb" ascii
      $x3 = "\\\\.\\Pnpkb" fullword ascii
      $s1 = "\\DosDevices\\Pnpkb" wide
      $s2 = "\\DosDevices\\PnpKb" wide
      $s3 = "\\Driver\\kbdhid" wide
      $s4 = "\\Device\\PnpKb" wide
      $s5 = "Microsoft  Windows Operating System" fullword wide
      $s6 = "hDevice == INVALID_HANDLE_VALUE" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 20KB and ( 1 of ( $x* ) and 1 of ( $s* ) )
}