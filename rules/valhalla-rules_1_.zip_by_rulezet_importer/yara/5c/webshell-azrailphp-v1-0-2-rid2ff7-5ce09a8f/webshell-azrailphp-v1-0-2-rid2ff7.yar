rule WebShell_aZRaiLPhp_v1_0_2_RID2FF7 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file aZRaiLPhp v1.0.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 12:19:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-11-23"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<font size='+1'color='#0000FF'>aZRaiLPhP'nin URL'si: http://$HTTP_HOST$RED" 
      $s4 = "$fileperm=base_convert($_POST['fileperm'],8,10);" fullword
      $s19 = "touch (\"$path/$dismi\") or die(\"Dosya Olu" fullword
      $s20 = "echo \"<div align=left><a href='./$this_file?dir=$path/$file'>G" fullword
   condition: 
      2 of them
}