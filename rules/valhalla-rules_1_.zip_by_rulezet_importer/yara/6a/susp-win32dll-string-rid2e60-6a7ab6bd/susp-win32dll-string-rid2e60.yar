rule SUSP_Win32dll_String_RID2E60 : DEMO SUSP {
   meta:
      description = "Detects suspicious string in executables"
      author = "Florian Roth"
      reference = "https://medium.com/@Sebdraven/apt-sidewinder-changes-theirs-ttps-to-install-their-backdoor-f92604a2739"
      date = "2018-10-24 11:11:51"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7bd7cec82ee98feed5872325c2f8fd9f0ea3a2f6cd0cd32bcbe27dbbfd0d7da1"
      tags = "DEMO, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "win32dll.dll" fullword ascii
   condition: 
      filesize < 60KB and all of them
}