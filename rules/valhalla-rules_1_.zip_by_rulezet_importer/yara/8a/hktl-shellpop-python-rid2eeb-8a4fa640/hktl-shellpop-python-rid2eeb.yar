rule HKTL_shellpop_Python_RID2EEB : DEMO HKTL SCRIPT T1059_006 T1070_003 {
   meta:
      description = "Detects malicious python shell"
      author = "Tobias Michalski"
      reference = "https://github.com/0x00-0x00/ShellPop"
      date = "2018-05-18 11:35:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "aee1c9e45a1edb5e462522e266256f68313e2ff5956a55f0a84f33bc6baa980b"
      tags = "DEMO, HKTL, SCRIPT, T1059_006, T1070_003"
      minimum_yara = "3.5.0"
      
   strings:
      $ = "os.putenv('HISTFILE', '/dev/null');" ascii
   condition: 
      filesize < 2KB and 1 of them
}