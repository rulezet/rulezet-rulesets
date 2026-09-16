rule TTP_XOR_MULT_DOSStub_0af8 {
  strings:
    $key_0af8 = { 5e 90 [2] 2a 88 [2] 6d 8a [2] 2a 9b [2] 64 97 [2] 68 9d [2] 7f 96 [2] 64 d8 [2] 59 }

  condition:
    any of them
}