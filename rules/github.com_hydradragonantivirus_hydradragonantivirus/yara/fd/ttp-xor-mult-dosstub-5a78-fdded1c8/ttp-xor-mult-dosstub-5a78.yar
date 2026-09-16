rule TTP_XOR_MULT_DOSStub_5a78 {
  strings:
    $key_5a78 = { 0e 10 [2] 7a 08 [2] 3d 0a [2] 7a 1b [2] 34 17 [2] 38 1d [2] 2f 16 [2] 34 58 [2] 09 }

  condition:
    any of them
}