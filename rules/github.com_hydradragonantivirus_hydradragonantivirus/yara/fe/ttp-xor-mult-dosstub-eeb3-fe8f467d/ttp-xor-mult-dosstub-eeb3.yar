rule TTP_XOR_MULT_DOSStub_eeb3 {
  strings:
    $key_eeb3 = { ba db [2] ce c3 [2] 89 c1 [2] ce d0 [2] 80 dc [2] 8c d6 [2] 9b dd [2] 80 93 [2] bd }

  condition:
    any of them
}