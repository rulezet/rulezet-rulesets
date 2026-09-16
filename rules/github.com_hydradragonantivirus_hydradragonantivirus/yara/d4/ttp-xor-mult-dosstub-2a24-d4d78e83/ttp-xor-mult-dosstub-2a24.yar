rule TTP_XOR_MULT_DOSStub_2a24 {
  strings:
    $key_2a24 = { 7e 4c [2] 0a 54 [2] 4d 56 [2] 0a 47 [2] 44 4b [2] 48 41 [2] 5f 4a [2] 44 04 [2] 79 }

  condition:
    any of them
}