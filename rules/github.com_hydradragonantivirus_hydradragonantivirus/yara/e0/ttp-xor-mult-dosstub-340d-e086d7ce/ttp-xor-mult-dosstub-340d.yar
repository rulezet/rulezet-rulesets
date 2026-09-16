rule TTP_XOR_MULT_DOSStub_340d {
  strings:
    $key_340d = { 60 65 [2] 14 7d [2] 53 7f [2] 14 6e [2] 5a 62 [2] 56 68 [2] 41 63 [2] 5a 2d [2] 67 }

  condition:
    any of them
}