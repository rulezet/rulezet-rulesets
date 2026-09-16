rule TTP_XOR_MULT_DOSStub_5d60 {
  strings:
    $key_5d60 = { 09 08 [2] 7d 10 [2] 3a 12 [2] 7d 03 [2] 33 0f [2] 3f 05 [2] 28 0e [2] 33 40 [2] 0e }

  condition:
    any of them
}