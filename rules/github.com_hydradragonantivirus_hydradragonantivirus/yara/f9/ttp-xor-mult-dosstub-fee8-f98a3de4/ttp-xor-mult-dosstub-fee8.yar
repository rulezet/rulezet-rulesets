rule TTP_XOR_MULT_DOSStub_fee8 {
  strings:
    $key_fee8 = { aa 80 [2] de 98 [2] 99 9a [2] de 8b [2] 90 87 [2] 9c 8d [2] 8b 86 [2] 90 c8 [2] ad }

  condition:
    any of them
}