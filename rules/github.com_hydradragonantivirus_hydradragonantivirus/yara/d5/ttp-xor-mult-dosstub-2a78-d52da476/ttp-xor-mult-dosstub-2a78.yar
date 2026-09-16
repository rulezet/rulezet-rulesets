rule TTP_XOR_MULT_DOSStub_2a78 {
  strings:
    $key_2a78 = { 7e 10 [2] 0a 08 [2] 4d 0a [2] 0a 1b [2] 44 17 [2] 48 1d [2] 5f 16 [2] 44 58 [2] 79 }

  condition:
    any of them
}