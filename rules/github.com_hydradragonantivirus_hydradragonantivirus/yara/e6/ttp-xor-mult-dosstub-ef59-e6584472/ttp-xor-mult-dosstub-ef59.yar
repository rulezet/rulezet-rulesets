rule TTP_XOR_MULT_DOSStub_ef59 {
  strings:
    $key_ef59 = { bb 31 [2] cf 29 [2] 88 2b [2] cf 3a [2] 81 36 [2] 8d 3c [2] 9a 37 [2] 81 79 [2] bc }

  condition:
    any of them
}