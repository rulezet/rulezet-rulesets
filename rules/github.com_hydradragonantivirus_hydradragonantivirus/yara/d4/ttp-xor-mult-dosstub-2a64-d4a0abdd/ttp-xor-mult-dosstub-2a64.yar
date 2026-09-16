rule TTP_XOR_MULT_DOSStub_2a64 {
  strings:
    $key_2a64 = { 7e 0c [2] 0a 14 [2] 4d 16 [2] 0a 07 [2] 44 0b [2] 48 01 [2] 5f 0a [2] 44 44 [2] 79 }

  condition:
    any of them
}