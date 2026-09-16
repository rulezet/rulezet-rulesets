rule TTP_XOR_MULT_DOSStub_5230 {
  strings:
    $key_5230 = { 06 58 [2] 72 40 [2] 35 42 [2] 72 53 [2] 3c 5f [2] 30 55 [2] 27 5e [2] 3c 10 [2] 01 }

  condition:
    any of them
}