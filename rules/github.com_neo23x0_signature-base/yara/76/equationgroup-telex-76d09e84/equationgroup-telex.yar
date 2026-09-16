rule EquationGroup_telex {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file telex"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "e9713b15fc164e0f64783e7a2eac189a40e0a60e2268bd7132cfdc624dfe54ef"
      id = "23571734-869d-5d68-9339-d82f168c2e47"
   strings:
      $x1 = "usage: %s -l [ netcat listener ] [ -p optional target port instead of 23 ] <ip>" fullword ascii
      $x2 = "target is not vulnerable. exiting" fullword ascii
      $s3 = "Sending final buffer: evil_blocks and shellcode..." fullword ascii
      $s4 = "Timeout waiting for daemon to die.  Exploit probably failed." fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 50KB and 1 of them )
}