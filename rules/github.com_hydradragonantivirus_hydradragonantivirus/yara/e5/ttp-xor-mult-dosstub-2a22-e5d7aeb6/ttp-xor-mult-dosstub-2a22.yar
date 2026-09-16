rule TTP_XOR_MULT_DOSStub_2a22 {
  strings:
    $key_2a22 = { 7e 4a [2] 0a 52 [2] 4d 50 [2] 0a 41 [2] 44 4d [2] 48 47 [2] 5f 4c [2] 44 02 [2] 79 }

  condition:
    any of them
}