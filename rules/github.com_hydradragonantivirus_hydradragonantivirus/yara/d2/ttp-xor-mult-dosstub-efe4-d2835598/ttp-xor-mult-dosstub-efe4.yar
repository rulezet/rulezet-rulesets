rule TTP_XOR_MULT_DOSStub_efe4 {
  strings:
    $key_efe4 = { bb 8c [2] cf 94 [2] 88 96 [2] cf 87 [2] 81 8b [2] 8d 81 [2] 9a 8a [2] 81 c4 [2] bc }

  condition:
    any of them
}