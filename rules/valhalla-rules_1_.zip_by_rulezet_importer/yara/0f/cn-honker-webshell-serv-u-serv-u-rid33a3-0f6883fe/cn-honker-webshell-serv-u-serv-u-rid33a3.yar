rule CN_Honker_Webshell_Serv_U_serv_u_RID33A3 : CHINA DEMO T1218_011 T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file serv-u.php"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 14:56:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-01-23"
      tags = "CHINA, DEMO, T1218_011, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "@readfile(\"c:\\\\winnt\\\\system32\\" ascii
      $s2 = "$sendbuf = \"PASS \".$_POST[\"password\"].\"\\r\\n\";" fullword ascii
      $s3 = "$cmd=\"cmd /c rundll32.exe $path,install $openPort $activeStr\";" fullword ascii
   condition: 
      filesize < 435KB and all of them
}