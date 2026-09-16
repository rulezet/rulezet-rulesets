rule Mimipenguin_SH_RID2C8D : DEMO HKTL LINUX SCRIPT T1003 {
   meta:
      description = "Detects Mimipenguin Password Extractor - Linux"
      author = "Florian Roth"
      reference = "https://github.com/huntergregal/mimipenguin"
      date = "2017-04-01 09:54:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, LINUX, SCRIPT, T1003"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$(echo $thishash | cut -d'$' -f 3)" ascii
      $s2 = "ps -eo pid,command | sed -rn '/gnome\\-keyring\\-daemon/p' | awk" ascii
      $s3 = "MimiPenguin Results:" ascii
   condition: 
      1 of them
}