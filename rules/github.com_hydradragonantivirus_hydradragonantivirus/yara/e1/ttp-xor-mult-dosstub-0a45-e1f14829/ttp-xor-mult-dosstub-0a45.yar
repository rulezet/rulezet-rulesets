rule TTP_XOR_MULT_DOSStub_0a45 {
  strings:
    $key_0a45 = { 5e 2d [2] 2a 35 [2] 6d 37 [2] 2a 26 [2] 64 2a [2] 68 20 [2] 7f 2b [2] 64 65 [2] 59 }

  condition:
    any of them
}