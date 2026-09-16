rule BluesPortScan {
   meta:
      description = "Auto-generated rule on file BluesPortScan.exe"
      author = "yarGen Yara Rule Generator by Florian Roth"
      hash = "6292f5fc737511f91af5e35643fc9eef"
      id = "4bcb8b7c-5e22-5496-9a29-66e85e3c3395"
   strings:
      $s0 = "This program was made by Volker Voss"
      $s1 = "JiBOo~SSB"
   condition:
      all of them
}