rule TTP_XOR_MULT_DOSStub_ef69 {
  strings:
    $key_ef69 = { bb 01 [2] cf 19 [2] 88 1b [2] cf 0a [2] 81 06 [2] 8d 0c [2] 9a 07 [2] 81 49 [2] bc }

  condition:
    any of them
}