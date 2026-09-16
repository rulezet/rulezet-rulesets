rule TTP_XOR_MULT_DOSStub_2126 {
  strings:
    $key_2126 = { 75 4e [2] 01 56 [2] 46 54 [2] 01 45 [2] 4f 49 [2] 43 43 [2] 54 48 [2] 4f 06 [2] 72 }

  condition:
    any of them
}