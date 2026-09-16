rule SUSP_OneNote_Embedded_FileDataStoreObject_Type_Jan23_2 {
   meta:
      description = "Detects suspicious embedded file types in OneNote files"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://blog.didierstevens.com/"
      date = "2023-01-27"
      score = 65
      id = "0664d202-ab4c-57b6-91ee-ea21ac08909e"
   strings:
      
      $a1 = { 00 e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac }

      $s1 = "<HTA:APPLICATION "
   condition:
      filesize < 5MB
      and $a1 
      and 1 of ($s*)
}