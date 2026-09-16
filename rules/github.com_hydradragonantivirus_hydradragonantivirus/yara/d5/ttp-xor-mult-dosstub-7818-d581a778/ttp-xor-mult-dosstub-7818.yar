rule TTP_XOR_MULT_DOSStub_7818 {
  strings:
    $key_7818 = { 2c 70 [2] 58 68 [2] 1f 6a [2] 58 7b [2] 16 77 [2] 1a 7d [2] 0d 76 [2] 16 38 [2] 2b }

  condition:
    any of them
}