rule SUSP_Qakbot_Uninstaller_File_Aug23_RID33CD : DEMO METARULE Qakbot SUSP {
   meta:
      description = "Detects Qakbot Uninstaller files used by the FBI and Dutch National Police in a disruption operation against the Qakbot in August 2023"
      author = "Florian Roth"
      reference = "https://www.justice.gov/usao-cdca/divisions/national-security-division/qakbot-resources"
      date = "2023-08-30 15:03:21"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, METARULE, Qakbot, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $xc1 = { E8 00 00 00 00 58 55 89 E5 89 C2 68 03 00 00 00 68 00 2C 00 00 05 20 0A 00 00 50 E8 05 00 00 00 83 C4 04 C9 C3 81 EC 08 01 00 00 53 55 56 57 6A 6B 58 6A 65 5B 6A 72 66 89 84 24 D4 00 00 00 33 } 
   condition: 
      $xc1
}