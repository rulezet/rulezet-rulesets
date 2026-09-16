rule Webshell_r57shell_antichat_RID3147 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files r57shell127.php, r57_iFX.php, r57_kartal.php, r57.php, antichat.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:15:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "513b7be8bd0595c377283a7c87b44b2e"
      hash2 = "1d912c55b96e2efe8ca873d6040e3b30"
      hash3 = "4108f28a9792b50d95f95b9e5314fa1e"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s6 = "$res   = @mysql_query(\"SHOW CREATE TABLE `\".$_POST['mysql_tbl'].\"`\", $d" 
      $s7 = "$sql1 .= $row[1].\"\\r\\n\\r\\n\";" fullword
      $s8 = "if(!empty($_POST['dif'])&&$fp) { @fputs($fp,$sql1.$sql2); }" fullword
      $s9 = "foreach($values as $k=>$v) {$values[$k] = addslashes($v);}" fullword
   condition: 
      2 of them
}