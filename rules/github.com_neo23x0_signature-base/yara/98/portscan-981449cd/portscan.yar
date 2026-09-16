rule portscan {
   meta:
      description = "Auto-generated rule on file portscan.exe"
      author = "yarGen Yara Rule Generator by Florian Roth"
      hash = "a8bfdb2a925e89a281956b1e3bb32348"
      id = "967d6e3b-ae0d-5f93-a20d-742fc010608d"
   strings:
      $s5 = "0    :SCAN BEGUN ON PORT:"
      $s6 = "0    :PORTSCAN READY."
   condition:
      all of them
}