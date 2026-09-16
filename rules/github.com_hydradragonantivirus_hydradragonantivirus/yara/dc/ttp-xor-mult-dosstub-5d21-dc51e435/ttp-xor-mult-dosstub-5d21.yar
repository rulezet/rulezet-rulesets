rule TTP_XOR_MULT_DOSStub_5d21 {
  strings:
    $key_5d21 = { 09 49 [2] 7d 51 [2] 3a 53 [2] 7d 42 [2] 33 4e [2] 3f 44 [2] 28 4f [2] 33 01 [2] 0e }

  condition:
    any of them
}