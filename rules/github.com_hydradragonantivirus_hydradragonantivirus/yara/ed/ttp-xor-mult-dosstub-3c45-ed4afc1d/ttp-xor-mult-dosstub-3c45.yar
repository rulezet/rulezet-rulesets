rule TTP_XOR_MULT_DOSStub_3c45 {
  strings:
    $key_3c45 = { 68 2d [2] 1c 35 [2] 5b 37 [2] 1c 26 [2] 52 2a [2] 5e 20 [2] 49 2b [2] 52 65 [2] 6f }

  condition:
    any of them
}