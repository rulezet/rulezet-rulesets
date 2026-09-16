rule Webshell_GFS_web_shell_ver_3_1_7_RID32FE : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files GFS web-shell ver 3.1.7 - PRiV8.php.txt, nshell.php.php.txt, gfs_sh.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 14:28:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "4a44d82da21438e32d4f514ab35c26b6"
      hash2 = "f618f41f7ebeb5e5076986a66593afd1"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "echo $uname.\"</font><br><b>\";" fullword
      $s3 = "while(!feof($f)) { $res.=fread($f,1024); }" fullword
      $s4 = "echo \"user=\".@get_current_user().\" uid=\".@getmyuid().\" gid=\".@getmygid()" 
   condition: 
      2 of them
}