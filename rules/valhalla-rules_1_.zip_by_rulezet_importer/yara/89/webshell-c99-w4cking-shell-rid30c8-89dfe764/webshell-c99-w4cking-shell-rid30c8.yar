rule Webshell_C99_w4cking_Shell_RID30C8 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects Web Shell from tennc webshell repo"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:54:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "d3f38a6dc54a73d304932d9227a739ec"
      hash2 = "9c34adbc8fd8d908cbb341734830f971"
      hash3 = "f2fa878de03732fbf5c86d656467ff50"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "echo \"<b>HEXDUMP:</b><nobr>" 
      $s4 = "if ($filestealth) {$stat = stat($d.$f);}" fullword
      $s5 = "while ($row = mysql_fetch_array($result, MYSQL_NUM)) { echo \"<tr><td>\".$r" 
      $s6 = "if ((mysql_create_db ($sql_newdb)) and (!empty($sql_newdb))) {echo \"DB " 
      $s8 = "echo \"<center><b>Server-status variables:</b><br><br>\";" fullword
      $s9 = "echo \"<textarea cols=80 rows=10>\".htmlspecialchars($encoded).\"</textarea>" 
   condition: 
      2 of them
}