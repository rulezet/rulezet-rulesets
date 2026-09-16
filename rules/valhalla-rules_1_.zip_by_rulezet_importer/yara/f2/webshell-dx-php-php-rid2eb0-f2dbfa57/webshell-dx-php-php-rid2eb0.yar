rule Webshell_Dx_php_php_RID2EB0 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Dx.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:25:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "print \"\\n\".'Tip: to view the file \"as is\" - open the page in <a href=\"'.Dx" 
      $s2 = "$DEF_PORTS=array (1=>'tcpmux (TCP Port Service Multiplexer)',2=>'Management Util" 
      $s3 = "$ra44  = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = $_SERVER['HTTP" 
   condition: 
      1 of them
}