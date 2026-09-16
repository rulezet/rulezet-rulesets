rule Webshell_iMHaPFtp_2_RID2E10 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file iMHaPFtp.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:58:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s8 = "if ($l) echo '<a href=\"' . $self . '?action=permission&amp;file=' . urlencode($" 
      $s9 = "return base64_decode('R0lGODlhEQANAJEDAMwAAP///5mZmf///yH5BAHoAwMALAAAAAARAA0AAA" 
   condition: 
      1 of them
}