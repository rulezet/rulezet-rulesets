rule TTP_XOR_MULT_DOSStub_7b45 {
  strings:
    $key_7b45 = { 2f 2d [2] 5b 35 [2] 1c 37 [2] 5b 26 [2] 15 2a [2] 19 20 [2] 0e 2b [2] 15 65 [2] 28 }

  condition:
    any of them
}