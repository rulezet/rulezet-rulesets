rule TTP_XOR_MULT_DOSStub_eff5 {
  strings:
    $key_eff5 = { bb 9d [2] cf 85 [2] 88 87 [2] cf 96 [2] 81 9a [2] 8d 90 [2] 9a 9b [2] 81 d5 [2] bc }

  condition:
    any of them
}