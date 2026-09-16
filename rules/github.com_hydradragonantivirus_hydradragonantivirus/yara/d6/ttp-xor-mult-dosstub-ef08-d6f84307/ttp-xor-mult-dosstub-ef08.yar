rule TTP_XOR_MULT_DOSStub_ef08 {
  strings:
    $key_ef08 = { bb 60 [2] cf 78 [2] 88 7a [2] cf 6b [2] 81 67 [2] 8d 6d [2] 9a 66 [2] 81 28 [2] bc }

  condition:
    any of them
}