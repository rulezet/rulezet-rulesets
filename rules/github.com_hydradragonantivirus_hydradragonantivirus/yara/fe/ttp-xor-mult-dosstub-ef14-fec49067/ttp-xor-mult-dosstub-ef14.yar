rule TTP_XOR_MULT_DOSStub_ef14 {
  strings:
    $key_ef14 = { bb 7c [2] cf 64 [2] 88 66 [2] cf 77 [2] 81 7b [2] 8d 71 [2] 9a 7a [2] 81 34 [2] bc }

  condition:
    any of them
}