rule TTP_XOR_MULT_DOSStub_fef1 {
  strings:
    $key_fef1 = { aa 99 [2] de 81 [2] 99 83 [2] de 92 [2] 90 9e [2] 9c 94 [2] 8b 9f [2] 90 d1 [2] ad }

  condition:
    any of them
}