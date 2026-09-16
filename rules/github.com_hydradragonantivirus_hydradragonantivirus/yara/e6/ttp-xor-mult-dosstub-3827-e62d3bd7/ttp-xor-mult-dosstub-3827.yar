rule TTP_XOR_MULT_DOSStub_3827 {
  strings:
    $key_3827 = { 6c 4f [2] 18 57 [2] 5f 55 [2] 18 44 [2] 56 48 [2] 5a 42 [2] 4d 49 [2] 56 07 [2] 6b }

  condition:
    any of them
}