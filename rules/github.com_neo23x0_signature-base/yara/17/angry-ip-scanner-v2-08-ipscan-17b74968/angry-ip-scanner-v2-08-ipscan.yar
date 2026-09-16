rule Angry_IP_Scanner_v2_08_ipscan {
   meta:
      description = "Auto-generated rule on file ipscan.exe"
      author = "yarGen Yara Rule Generator by Florian Roth"
      hash = "70cf2c09776a29c3e837cb79d291514a"
      id = "5fbcbb95-6cd4-5587-bf44-5b5ed133ce5e"
   strings:
      $s0 = "_H/EnumDisplay/"
      $s5 = "ECTED.MSVCRT0x"
      $s8 = "NotSupported7"
   condition:
      all of them
}