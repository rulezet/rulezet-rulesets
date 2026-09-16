rule TTP_XOR_MULT_DOSStub_feb3 {
  strings:
    $key_feb3 = { aa db [2] de c3 [2] 99 c1 [2] de d0 [2] 90 dc [2] 9c d6 [2] 8b dd [2] 90 93 [2] ad }

  condition:
    any of them
}