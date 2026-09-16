rule Webshell_PHPJackal_itsecteam_shell_RID3469 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files itsec.php, PHPJackal.php, itsecteam_shell.php, jHn.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 15:29:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "e2830d3286001d1455479849aacbbb38"
      hash2 = "bd6d3b2763c705a01cc2b3f105a25fa4"
      hash3 = "40c6ecf77253e805ace85f119fe1cebb"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$link=pg_connect(\"host=$host dbname=$db user=$user password=$pass\");" fullword
      $s6 = "while($data=ocifetchinto($stm,$data,OCI_ASSOC+OCI_RETURN_NULLS))$res.=implode('|" 
      $s9 = "while($data=pg_fetch_row($result))$res.=implode('|-|-|-|-|-|',$data).'|+|+|+|+|+" 
   condition: 
      2 of them
}