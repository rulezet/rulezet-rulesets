rule TTP_XOR_MULT_DOSStub_fef7 {
  strings:
    $key_fef7 = { aa 9f [2] de 87 [2] 99 85 [2] de 94 [2] 90 98 [2] 9c 92 [2] 8b 99 [2] 90 d7 [2] ad }

  condition:
    any of them
}