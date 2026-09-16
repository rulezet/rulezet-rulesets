rule TTP_XOR_MULT_DOSStub_3966 {
  strings:
    $key_3966 = { 6d 0e [2] 19 16 [2] 5e 14 [2] 19 05 [2] 57 09 [2] 5b 03 [2] 4c 08 [2] 57 46 [2] 6a }

  condition:
    any of them
}