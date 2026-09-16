rule CN_Honker__PostgreSQL_mysql_injectV1_1_Creak_Oracle_SQLServer_inject_Creaked_RID442C : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - from files PostgreSQL.exe, mysql_injectV1.1_Creak.exe, Oracle.exe, SQLServer_inject_Creaked.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 02:41:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a1f066789f48a76023598c5777752c15f91b76b0"
      hash2 = "0264f4efdba09eaf1e681220ba96de8498ab3580"
      hash3 = "af3c41756ec8768483a4cf59b2e639994426e2c2"
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "zhaoxypass@yahoo.com.cn" fullword ascii
      $s2 = "Mozilla/3.0 (compatible; Indy Library)" fullword ascii
      $s3 = "ProxyParams.ProxyPort" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and all of them
}