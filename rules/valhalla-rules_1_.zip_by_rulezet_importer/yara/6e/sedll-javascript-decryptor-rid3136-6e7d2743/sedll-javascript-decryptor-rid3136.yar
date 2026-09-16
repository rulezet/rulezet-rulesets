rule SeDLL_Javascript_Decryptor_RID3136 : APT DEMO EXE FILE T1218_010 sedll {
   meta:
      description = "Detects SeDll - DLL is used for decrypting and executing another JavaScript backdoor such as Orz"
      author = "Florian Roth"
      reference = "https://www.proofpoint.com/us/threat-insight/post/leviathan-espionage-actor-spearphishes-maritime-and-defense-targets"
      date = "2017-10-18 13:12:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "146aa9a0ec013aa5bdba9ea9d29f59d48d43bc17c6a20b74bb8c521dbb5bc6f4"
      tags = "APT, DEMO, EXE, FILE, T1218_010, sedll"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "SEDll_Win32.dll" fullword ascii
      $x2 = "regsvr32 /s \"%s\" DR __CIM__" wide
      $s1 = "WScriptW" fullword ascii
      $s2 = "IWScript" fullword ascii
      $s3 = "%s\\%s~%d" fullword wide
      $s4 = "PutBlockToFileWW" fullword ascii
      $s5 = "CheckUpAndDownWW" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 40KB and ( 1 of ( $x* ) or 4 of them )
}