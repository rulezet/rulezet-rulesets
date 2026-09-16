rule mimipenguin_1_RID2C43 : DEMO FILE HKTL {
   meta:
      description = "Detects Mimipenguin hack tool"
      author = "Florian Roth"
      reference = "https://github.com/huntergregal/mimipenguin"
      date = "2017-07-08 09:41:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9e8d13fe27c93c7571075abf84a839fd1d31d8f2e3e48b3f4c6c13f7afcf8cbd"
      tags = "DEMO, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "self._strings_dump += strings(dump_process(target_pid))" fullword ascii
      $x2 = "def _dump_target_processes(self):" fullword ascii
      $x3 = "self._target_processes = ['sshd:']" fullword ascii
      $x4 = "GnomeKeyringPasswordFinder()" ascii
   condition: 
      ( uint16 ( 0 ) == 0x2123 and filesize < 20KB and 1 of them )
}