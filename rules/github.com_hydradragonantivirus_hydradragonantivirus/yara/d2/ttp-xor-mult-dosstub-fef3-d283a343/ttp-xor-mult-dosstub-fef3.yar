rule TTP_XOR_MULT_DOSStub_fef3 {
  strings:
    $key_fef3 = { aa 9b [2] de 83 [2] 99 81 [2] de 90 [2] 90 9c [2] 9c 96 [2] 8b 9d [2] 90 d3 [2] ad }

  condition:
    any of them
}