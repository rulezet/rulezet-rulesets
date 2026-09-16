rule TTP_XOR_MULT_DOSStub_eee6 {
  strings:
    $key_eee6 = { ba 8e [2] ce 96 [2] 89 94 [2] ce 85 [2] 80 89 [2] 8c 83 [2] 9b 88 [2] 80 c6 [2] bd }

  condition:
    any of them
}