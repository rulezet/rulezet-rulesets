rule APT_MAL_FalseFont_Backdoor_Jan24_RID3272 : APT DEMO EXE FILE G0064 MAL T1003 {
   meta:
      description = "Detects FalseFont backdoor, related to Peach Sandstorm APT"
      author = "X__Junior, Jonathan Peters"
      reference = "https://twitter.com/MsftSecIntel/status/1737895710169628824"
      date = "2024-01-11 14:05:31"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, EXE, FILE, G0064, MAL, T1003"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Agent.Core.WPF.App" ascii
      $x2 = "3EzuNZ0RN3h3oV7rzILktSHSaHk+5rtcWOr0mlA1CUA=" wide
      $x3 = "viOIZ9cX59qDDjMHYsz1Yw==" wide
      $sa1 = "StopSendScreen" wide
      $sa2 = "Decryption failed :(" wide
      $sb1 = "{0}     {1}     {2}     {3}" wide
      $sb2 = "\\BraveSoftware\\Brave-Browser\\User Data\\" wide
      $sb3 = "select * from logins" wide
      $sb4 = "Loginvault.db" wide
      $sb5 = "password_value" wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and ( 1 of ( $x* ) or all of ( $sa* ) or all of ( $sb* ) or ( 1 of ( $sa* ) and 4 of ( $sb* ) ) )
}