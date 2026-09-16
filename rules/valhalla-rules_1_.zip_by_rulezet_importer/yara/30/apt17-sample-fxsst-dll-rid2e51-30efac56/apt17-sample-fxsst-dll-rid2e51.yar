rule APT17_Sample_FXSST_DLL_RID2E51 : APT DEMO EXE FILE G0025 {
   meta:
      description = "Detects Samples related to APT17 activity - file FXSST.DLL"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2015/05/hiding_in_plain_sigh.html"
      date = "2015-05-14 11:09:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      tags = "APT, DEMO, EXE, FILE, G0025"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Microsoft? Windows? Operating System" fullword wide
      $x2 = "fxsst.dll" fullword ascii
      $y1 = "DllRegisterServer" fullword ascii
      $y2 = ".cSV" fullword ascii
      $s1 = "GetLastActivePopup" 
      $s2 = "Sleep" 
      $s3 = "GetModuleFileName" 
      $s4 = "VirtualProtect" 
      $s5 = "HeapAlloc" 
      $s6 = "GetProcessHeap" 
      $s7 = "GetCommandLine" 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 800KB and ( all of ( $x* ) or all of ( $y* ) ) and all of ( $s* )
}