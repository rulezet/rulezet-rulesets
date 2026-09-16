rule HKTL_ChromePass_Sep16_RID2E86 : DEMO EXE FILE HKTL {
   meta:
      description = "Detects a tool used by APT groups - file ChromePass.exe"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://goo.gl/igxLyF"
      date = "2016-09-08 11:18:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2025-03-10"
      hash1 = "5ff43049ae18d03dcc74f2be4a870c7056f6cfb5eb636734cca225140029de9a"
      id = "950b9761-bdfd-514b-90ea-a1454d35ce5a"
      tags = "DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "\\Release\\ChromePass.pdb" ascii
      $x2 = "Windows Protect folder for getting the encryption keys" wide
      $x3 = "Chrome User Data folder where the password file is stored" wide
      $s1 = "Opera Software\\Opera Stable\\Login Data" fullword wide
      $s2 = "Yandex\\YandexBrowser\\User Data\\Default\\Login Data" fullword wide
      $s3 = "Load the passwords from another Windows user or external drive: " fullword wide
      $s4 = "Windows Login Password:" fullword wide
      $s5 = "SELECT origin_url, action_url, username_element, username_value, password_element, password_value, signon_realm, date_created fr" ascii
      $s6 = "Chrome Password Recovery" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 700KB and 1 of ( $x* ) ) or ( 5 of them )
}