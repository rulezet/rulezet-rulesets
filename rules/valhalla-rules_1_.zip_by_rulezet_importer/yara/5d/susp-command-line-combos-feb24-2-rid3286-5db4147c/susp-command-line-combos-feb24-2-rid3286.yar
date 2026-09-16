rule SUSP_Command_Line_Combos_Feb24_2_RID3286 : DEMO SCRIPT SUSP {
   meta:
      description = "Detects suspicious command line combinations often found in post exploitation activities"
      author = "Florian Roth"
      reference = "https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708"
      date = "2024-02-23 14:08:51"
      score = 45
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $sa1 = " | iex" 
      $sa2 = "iwr -UseBasicParsing " 
   condition: 
      filesize < 2MB and all of them
}