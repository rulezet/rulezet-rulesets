rule TTP_XOR_MULT_DOSStub_2122 {
  strings:
    $key_2122 = { 75 4a [2] 01 52 [2] 46 50 [2] 01 41 [2] 4f 4d [2] 43 47 [2] 54 4c [2] 4f 02 [2] 72 }

  condition:
    any of them
}