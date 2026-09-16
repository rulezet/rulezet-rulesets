rule Msfpayloads_msf_exe_2_RID2F6B : APT DEMO METASPLOIT {
   meta:
      description = "Metasploit Payloads - file msf-exe.aspx"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09 11:56:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3a2f7a654c1100e64d8d3b4cd39165fba3b101bbcce6dd0f70dae863da338401"
      tags = "APT, DEMO, METASPLOIT"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "= new System.Diagnostics.Process();" fullword ascii
      $x2 = ".StartInfo.UseShellExecute = true;" fullword ascii
      $x3 = ", \"svchost.exe\");" ascii
      $s4 = " = Path.GetTempPath();" ascii
   condition: 
      all of them
}