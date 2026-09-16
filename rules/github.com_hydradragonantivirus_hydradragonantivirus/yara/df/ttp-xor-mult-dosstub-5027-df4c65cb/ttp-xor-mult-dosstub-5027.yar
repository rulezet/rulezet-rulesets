rule TTP_XOR_MULT_DOSStub_5027 {
  strings:
    $key_5027 = { 04 4f [2] 70 57 [2] 37 55 [2] 70 44 [2] 3e 48 [2] 32 42 [2] 25 49 [2] 3e 07 [2] 03 }

  condition:
    any of them
}