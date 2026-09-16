rule SUSP_GObfuscate_May21 {
   meta:
      description = "Identifies binaries obfuscated with gobfuscate"
      author = "James Quinn, Paul Hager (merged with new similar pattern)"
      reference = "https://github.com/unixpickle/gobfuscate"
      date = "2021-05-14"
      modified = "2024-04-02"
      score = 70
      id = "ae518296-b1c3-568c-bae0-3e0a6f7600ba"
   strings:
      $s1 = { 0F B6 ?? ?? ?? 0F B6 ?? ?? ?? 31 D? [0-1] 88 ?? ?? ?? 48 FF C? 48 83 F? ?? 7C E6 48 }
                  $s2 = { 0F B6 ?? ?? ?? 31 DA 88 ?? ?? ?? 40 83 ?? ?? 7D 09 0F B6 }
   condition:
      filesize < 50MB and any of them
}