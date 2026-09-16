import "pe"
rule Winexe_RemoteExec_RID2DD1 : DEMO EXE FILE G0007 HKTL RUSSIA T1219 T1569_002 {
   meta:
      description = "Winexe tool for remote execution (also used by Sofacy group)"
      author = "Florian Roth"
      reference = "http://dokumente.linksfraktion.de/inhalt/report-orig.pdf"
      date = "2015-06-19 10:48:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2021-02-11"
      hash1 = "5130f600cd9a9cdc82d4bad938b20cbd2f699aadb76e7f3f1a93602330d9997d"
      hash2 = "d19dfdbe747e090c5aa2a70cc10d081ac1aa88f360c3f378288a3651632c4429"
      tags = "DEMO, EXE, FILE, G0007, HKTL, RUSSIA, T1219, T1569_002"
      required_modules = "pe"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "error Cannot LogonUser(%s,%s,%s) %d" ascii fullword
      $s2 = "error Cannot ImpersonateNamedPipeClient %d" ascii fullword
      $s3 = "\\\\.\\pipe\\ahexec" fullword ascii
      $s4 = "\\\\.\\pipe\\wmcex" fullword ascii
      $s5 = "implevel" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 115KB and ( 3 of them or pe.imphash ( ) == "2f8a475933ac82b8e09eaf26b396b54d" )
}