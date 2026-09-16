rule CN_Honker_Webshell_T00ls_Lpk_Sethc_v4_mail_RID36D6 : CHINA DEMO T1505_003 T1546_008 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file mail.php"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 17:12:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, T1546_008, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "if (!$this->smtp_putcmd(\"AUTH LOGIN\", base64_encode($this->user)))" fullword ascii
      $s2 = "$this->smtp_debug(\"> \".$cmd.\"\\n\");" fullword ascii
   condition: 
      filesize < 39KB and all of them
}