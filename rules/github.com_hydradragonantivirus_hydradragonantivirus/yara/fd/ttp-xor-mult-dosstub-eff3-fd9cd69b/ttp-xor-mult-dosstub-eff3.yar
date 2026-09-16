rule TTP_XOR_MULT_DOSStub_eff3 {
  strings:
    $key_eff3 = { bb 9b [2] cf 83 [2] 88 81 [2] cf 90 [2] 81 9c [2] 8d 96 [2] 9a 9d [2] 81 d3 [2] bc }

  condition:
    any of them
}