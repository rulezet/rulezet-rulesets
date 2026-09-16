rule TTP_XOR_MULT_DOSStub_3522 {
  strings:
    $key_3522 = { 61 4a [2] 15 52 [2] 52 50 [2] 15 41 [2] 5b 4d [2] 57 47 [2] 40 4c [2] 5b 02 [2] 66 }

  condition:
    any of them
}