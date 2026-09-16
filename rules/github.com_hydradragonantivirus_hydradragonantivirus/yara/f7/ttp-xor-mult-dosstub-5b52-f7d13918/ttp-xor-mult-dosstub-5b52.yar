rule TTP_XOR_MULT_DOSStub_5b52 {
  strings:
    $key_5b52 = { 0f 3a [2] 7b 22 [2] 3c 20 [2] 7b 31 [2] 35 3d [2] 39 37 [2] 2e 3c [2] 35 72 [2] 08 }

  condition:
    any of them
}