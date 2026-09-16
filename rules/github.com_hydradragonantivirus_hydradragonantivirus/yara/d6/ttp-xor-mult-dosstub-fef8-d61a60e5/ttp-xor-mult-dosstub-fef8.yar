rule TTP_XOR_MULT_DOSStub_fef8 {
  strings:
    $key_fef8 = { aa 90 [2] de 88 [2] 99 8a [2] de 9b [2] 90 97 [2] 9c 9d [2] 8b 96 [2] 90 d8 [2] ad }

  condition:
    any of them
}