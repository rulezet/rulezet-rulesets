rule Webshell_phpspy_arabicspy_RID3167 : DEMO SCRIPT T1007 T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files shell.php, phpspy_2006.php, arabicspy.php, hkrkoz.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:21:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "40a1f840111996ff7200d18968e42cfe"
      hash2 = "e0202adff532b28ef1ba206cf95962f2"
      hash3 = "802f5cae46d394b297482fd0c27cb2fc"
      tags = "DEMO, SCRIPT, T1007, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s5 = "$prog = isset($_POST['prog']) ? $_POST['prog'] : \"/c net start > \".$pathname." 
   condition: 
      all of them
}