rule TTP_XOR_MULT_DOSStub_5b45 {
  strings:
    $key_5b45 = { 0f 2d [2] 7b 35 [2] 3c 37 [2] 7b 26 [2] 35 2a [2] 39 20 [2] 2e 2b [2] 35 65 [2] 08 }

  condition:
    any of them
}