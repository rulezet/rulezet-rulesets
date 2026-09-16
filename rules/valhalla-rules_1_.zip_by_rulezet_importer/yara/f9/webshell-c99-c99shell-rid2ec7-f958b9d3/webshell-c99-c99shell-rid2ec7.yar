rule Webshell_c99_c99shell_RID2EC7 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files c99.php, c66.php, c99-shadows-mod.php, c99shell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:29:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "0f5b9238d281bc6ac13406bb24ac2a5b"
      hash2 = "68c0629d08b1664f5bcce7d7f5f71d22"
      hash3 = "048ccc01b873b40d57ce25a4c56ea717"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "  if (unlink(_FILE_)) {@ob_clean(); echo \"Thanks for using c99shell v.\".$shv" 
      $s3 = "  \"c99sh_backconn.pl\"=>array(\"Using PERL\",\"perl %path %host %port\")," fullword
      $s4 = "<br><TABLE style=\"BORDER-COLLAPSE: collapse\" cellSpacing=0 borderColorDark=#66" 
      $s7 = "   elseif (!$data = c99getsource($bind[\"src\"])) {echo \"Can't download sources" 
      $s8 = "  \"c99sh_datapipe.pl\"=>array(\"Using PERL\",\"perl %path %localport %remotehos" 
      $s9 = "   elseif (!$data = c99getsource($bc[\"src\"])) {echo \"Can't download sources!" 
   condition: 
      2 of them
}