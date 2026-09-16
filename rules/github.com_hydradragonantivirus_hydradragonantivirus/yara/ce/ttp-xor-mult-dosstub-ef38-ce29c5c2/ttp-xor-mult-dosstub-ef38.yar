rule TTP_XOR_MULT_DOSStub_ef38 {
  strings:
    $key_ef38 = { bb 50 [2] cf 48 [2] 88 4a [2] cf 5b [2] 81 57 [2] 8d 5d [2] 9a 56 [2] 81 18 [2] bc }

  condition:
    any of them
}