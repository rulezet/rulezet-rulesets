rule TTP_XOR_MULT_DOSStub_6060 {
  strings:
    $key_6060 = { 34 08 [2] 40 10 [2] 07 12 [2] 40 03 [2] 0e 0f [2] 02 05 [2] 15 0e [2] 0e 40 [2] 33 }

  condition:
    any of them
}