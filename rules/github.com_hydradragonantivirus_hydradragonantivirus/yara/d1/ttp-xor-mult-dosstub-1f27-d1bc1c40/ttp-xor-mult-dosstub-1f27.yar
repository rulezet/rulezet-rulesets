rule TTP_XOR_MULT_DOSStub_1f27 {
  strings:
    $key_1f27 = { 4b 4f [2] 3f 57 [2] 78 55 [2] 3f 44 [2] 71 48 [2] 7d 42 [2] 6a 49 [2] 71 07 [2] 4c }

  condition:
    any of them
}