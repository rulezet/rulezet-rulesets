rule TTP_XOR_MULT_DOSStub_2a08 {
  strings:
    $key_2a08 = { 7e 60 [2] 0a 78 [2] 4d 7a [2] 0a 6b [2] 44 67 [2] 48 6d [2] 5f 66 [2] 44 28 [2] 79 }

  condition:
    any of them
}