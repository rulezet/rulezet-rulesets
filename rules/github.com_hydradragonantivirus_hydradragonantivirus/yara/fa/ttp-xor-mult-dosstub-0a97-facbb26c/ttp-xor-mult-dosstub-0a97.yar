rule TTP_XOR_MULT_DOSStub_0a97 {
  strings:
    $key_0a97 = { 5e ff [2] 2a e7 [2] 6d e5 [2] 2a f4 [2] 64 f8 [2] 68 f2 [2] 7f f9 [2] 64 b7 [2] 59 }

  condition:
    any of them
}