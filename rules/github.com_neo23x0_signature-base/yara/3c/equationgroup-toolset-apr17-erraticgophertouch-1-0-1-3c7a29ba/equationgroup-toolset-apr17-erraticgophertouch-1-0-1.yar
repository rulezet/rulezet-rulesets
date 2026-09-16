rule EquationGroup_Toolset_Apr17_Erraticgophertouch_1_0_1 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "729eacf20fe71bd74e57a6b829b45113c5d45003933118b53835779f0b049bad"
      id = "9f03a4b6-69ab-5cef-876c-1e86ef2afe10"
   strings:
      $x1 = "[-] Unable to connect to broswer named pipe, target is NOT vulnerable" fullword ascii
      $x2 = "[-] Unable to bind to Dimsvc RPC syntax, target is NOT vulnerable" fullword ascii
      $x3 = "[+] Bound to Dimsvc, target IS vulnerable" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 30KB and 1 of them )
}