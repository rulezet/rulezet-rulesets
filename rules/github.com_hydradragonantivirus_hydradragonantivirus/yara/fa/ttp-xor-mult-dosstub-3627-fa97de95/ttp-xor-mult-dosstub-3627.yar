rule TTP_XOR_MULT_DOSStub_3627 {
  strings:
    $key_3627 = { 62 4f [2] 16 57 [2] 51 55 [2] 16 44 [2] 58 48 [2] 54 42 [2] 43 49 [2] 58 07 [2] 65 }

  condition:
    any of them
}