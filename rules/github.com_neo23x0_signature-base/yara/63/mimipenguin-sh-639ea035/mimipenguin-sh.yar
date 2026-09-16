rule Mimipenguin_SH {
   meta:
      description = "Detects Mimipenguin Password Extractor - Linux"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/huntergregal/mimipenguin"
      date = "2017-04-01"
      id = "c670f6fe-562d-598f-a73f-45e4ab234f7d"
   strings:
      $s1 = "$(echo $thishash | cut -d'$' -f 3)" ascii
      $s2 = "ps -eo pid,command | sed -rn '/gnome\\-keyring\\-daemon/p' | awk" ascii
      $s3 = "MimiPenguin Results:" ascii
   condition:
      1 of them
}