rule TTP_XOR_MULT_DOSStub_2230 {
  strings:
    $key_2230 = { 76 58 [2] 02 40 [2] 45 42 [2] 02 53 [2] 4c 5f [2] 40 55 [2] 57 5e [2] 4c 10 [2] 71 }

  condition:
    any of them
}