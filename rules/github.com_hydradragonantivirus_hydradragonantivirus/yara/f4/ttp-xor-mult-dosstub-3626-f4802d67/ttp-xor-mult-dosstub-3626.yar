rule TTP_XOR_MULT_DOSStub_3626 {
  strings:
    $key_3626 = { 62 4e [2] 16 56 [2] 51 54 [2] 16 45 [2] 58 49 [2] 54 43 [2] 43 48 [2] 58 06 [2] 65 }

  condition:
    any of them
}