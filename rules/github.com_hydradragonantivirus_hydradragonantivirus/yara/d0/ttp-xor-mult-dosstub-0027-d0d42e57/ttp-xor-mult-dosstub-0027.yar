rule TTP_XOR_MULT_DOSStub_0027 {
  strings:
    $key_0027 = { 54 4f [2] 20 57 [2] 67 55 [2] 20 44 [2] 6e 48 [2] 62 42 [2] 75 49 [2] 6e 07 [2] 53 }

  condition:
    any of them
}