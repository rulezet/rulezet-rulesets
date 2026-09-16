rule TTP_XOR_MULT_DOSStub_3327 {
  strings:
    $key_3327 = { 67 4f [2] 13 57 [2] 54 55 [2] 13 44 [2] 5d 48 [2] 51 42 [2] 46 49 [2] 5d 07 [2] 60 }

  condition:
    any of them
}