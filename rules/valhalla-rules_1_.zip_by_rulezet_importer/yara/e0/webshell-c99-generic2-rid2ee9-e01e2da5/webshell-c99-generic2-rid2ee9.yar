rule Webshell_c99_generic2_RID2EE9 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated "
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:34:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3ca5886cd54d495dc95793579611f59a"
      hash2 = "9c5bb5e3a46ec28039e8986324e42792"
      hash3 = "433706fdc539238803fd47c4394b5109"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = " if ($mode & 0x200) {$world[\"execute\"] = ($world[\"execute\"] == \"x\")?\"t\":" 
      $s1 = " $group[\"execute\"] = ($mode & 00010)?\"x\":\"-\";" fullword
   condition: 
      all of them
}