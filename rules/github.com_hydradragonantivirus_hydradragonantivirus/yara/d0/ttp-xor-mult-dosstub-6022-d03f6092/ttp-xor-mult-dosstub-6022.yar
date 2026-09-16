rule TTP_XOR_MULT_DOSStub_6022 {
  strings:
    $key_6022 = { 34 4a [2] 40 52 [2] 07 50 [2] 40 41 [2] 0e 4d [2] 02 47 [2] 15 4c [2] 0e 02 [2] 33 }

  condition:
    any of them
}