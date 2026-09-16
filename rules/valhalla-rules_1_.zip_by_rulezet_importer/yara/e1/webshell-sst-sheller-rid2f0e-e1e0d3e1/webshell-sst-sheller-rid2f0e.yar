rule Webshell_Sst_Sheller_RID2F0E : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file Sst-Sheller.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:40:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "echo \"<a href='?page=filemanager&id=fm&fchmod=$dir$file'>" 
      $s3 = "<? unlink($filename); unlink($filename1); unlink($filename2); unlink($filename3)" 
   condition: 
      all of them
}