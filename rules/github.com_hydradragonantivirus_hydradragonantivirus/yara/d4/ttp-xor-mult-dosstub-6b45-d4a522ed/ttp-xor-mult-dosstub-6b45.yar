rule TTP_XOR_MULT_DOSStub_6b45 {
  strings:
    $key_6b45 = { 3f 2d [2] 4b 35 [2] 0c 37 [2] 4b 26 [2] 05 2a [2] 09 20 [2] 1e 2b [2] 05 65 [2] 38 }

  condition:
    any of them
}