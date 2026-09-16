rule TTP_XOR_MULT_DOSStub_09a3 {
  strings:
    $key_09a3 = { 5d cb [2] 29 d3 [2] 6e d1 [2] 29 c0 [2] 67 cc [2] 6b c6 [2] 7c cd [2] 67 83 [2] 5a }

  condition:
    any of them
}