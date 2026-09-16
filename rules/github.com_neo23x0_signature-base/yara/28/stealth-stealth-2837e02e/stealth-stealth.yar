rule stealth_Stealth {
   meta:
      description = "Auto-generated rule on file Stealth.exe"
      author = "yarGen Yara Rule Generator by Florian Roth"
      hash = "8ce3a386ce0eae10fc2ce0177bbc8ffa"
      id = "5f45882e-3e27-596d-8725-fad380e1c297"
   strings:
      $s3 = "<table width=\"60%\" bgcolor=\"black\" cellspacing=\"0\" cellpadding=\"2\" border=\"1\" bordercolor=\"white\"><tr><td>"
      $s6 = "This tool may be used only by system administrators. I am not responsible for "
   condition:
      all of them
}