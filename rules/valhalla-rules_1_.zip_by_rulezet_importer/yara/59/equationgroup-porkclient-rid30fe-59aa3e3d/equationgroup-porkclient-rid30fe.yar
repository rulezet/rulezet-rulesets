rule EquationGroup_porkclient_RID30FE : APT DEMO FILE G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file porkclient"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 13:03:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "5c14e3bcbf230a1d7e2909876b045e34b1486c8df3c85fb582d9c93ad7c57748"
      tags = "APT, DEMO, FILE, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "-c COMMAND: shell command string" fullword ascii
      $s2 = "Cannot combine shell command mode with args to do socket reuse" fullword ascii
      $s3 = "-r: Reuse socket for Nopen connection (requires -t, -d, -f, -n, NO -c)" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 30KB and 1 of them )
}