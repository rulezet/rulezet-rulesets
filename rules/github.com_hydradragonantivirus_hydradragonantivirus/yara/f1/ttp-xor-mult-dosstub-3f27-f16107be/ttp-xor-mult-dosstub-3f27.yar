rule TTP_XOR_MULT_DOSStub_3f27 {
  strings:
    $key_3f27 = { 6b 4f [2] 1f 57 [2] 58 55 [2] 1f 44 [2] 51 48 [2] 5d 42 [2] 4a 49 [2] 51 07 [2] 6c }

  condition:
    any of them
}