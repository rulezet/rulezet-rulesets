rule TTP_XOR_MULT_DOSStub_0a18 {
  strings:
    $key_0a18 = { 5e 70 [2] 2a 68 [2] 6d 6a [2] 2a 7b [2] 64 77 [2] 68 7d [2] 7f 76 [2] 64 38 [2] 59 }

  condition:
    any of them
}