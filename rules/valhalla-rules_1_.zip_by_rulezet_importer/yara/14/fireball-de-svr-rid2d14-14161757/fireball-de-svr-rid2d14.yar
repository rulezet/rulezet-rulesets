rule Fireball_de_svr_RID2D14 : APT DEMO EXE FILE T1218_011 {
   meta:
      description = "Detects Fireball malware - file de_svr.exe"
      author = "Florian Roth"
      reference = "https://blog.checkpoint.com/research/fireball-chinese-malware-250-million-infection/"
      date = "2017-06-02 10:16:31"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "f964a4b95d5c518fd56f06044af39a146d84b801d9472e022de4c929a5b8fdcc"
      tags = "APT, DEMO, EXE, FILE, T1218_011"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "cmd.exe /c MD " fullword ascii
      $s2 = "rundll32.exe \"%s\",%s" fullword wide
      $s3 = "http://d12zpbetgs1pco.cloudfront.net/Weatherapi/shell" fullword wide
      $s4 = "C:\\v3\\exe\\de_svr_inst.pdb" fullword ascii
      $s5 = "Internet Connect Failed!" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 3000KB and 4 of them )
}