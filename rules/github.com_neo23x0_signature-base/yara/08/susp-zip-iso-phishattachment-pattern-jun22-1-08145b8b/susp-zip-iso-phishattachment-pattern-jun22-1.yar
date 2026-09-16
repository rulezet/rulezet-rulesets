rule SUSP_ZIP_ISO_PhishAttachment_Pattern_Jun22_1 {
   meta:
      description = "Detects suspicious small base64 encoded ZIP files (MIME email attachments) with .iso files as content as often used in phishing attacks"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2022-06-23"
      score = 65
      id = "638541a6-d2d4-513e-978c-9d1b9f5e3b71"
   strings:
      $pkzip_base64_1 = { 0A 55 45 73 44 42 }
      $pkzip_base64_2 = { 0A 55 45 73 44 42 }
      $pkzip_base64_3 = { 0A 55 45 73 48 43 }

      $iso_1 = "Lmlzb1BL"
      $iso_2 = "5pc29QS"
      $iso_3 = "uaXNvUE"
   condition:
      filesize < 2000KB and 1 of ($pk*) and 1 of ($iso*)
}