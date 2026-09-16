rule TTP_XOR_MULT_DOSStub_2221 {
  strings:
    $key_2221 = { 76 49 [2] 02 51 [2] 45 53 [2] 02 42 [2] 4c 4e [2] 40 44 [2] 57 4f [2] 4c 01 [2] 71 }

  condition:
    any of them
}