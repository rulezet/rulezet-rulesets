rule HKTL_Mithril_tool_RID2D99 : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file Mithril.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 10:38:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "OpenProcess error!" 
      $s1 = "WriteProcessMemory error!" 
      $s4 = "GetProcAddress error!" 
      $s5 = "HHt`HHt\\" 
      $s6 = "Cmaudi0" 
      $s7 = "CreateRemoteThread error!" 
      $s8 = "Kernel32" 
      $s9 = "VirtualAllocEx error!" 
   condition: 
      all of them
}