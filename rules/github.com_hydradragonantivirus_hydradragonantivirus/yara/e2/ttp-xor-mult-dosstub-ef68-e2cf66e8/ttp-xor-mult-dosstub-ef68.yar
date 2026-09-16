rule TTP_XOR_MULT_DOSStub_ef68 {
  strings:
    $key_ef68 = { bb 00 [2] cf 18 [2] 88 1a [2] cf 0b [2] 81 07 [2] 8d 0d [2] 9a 06 [2] 81 48 [2] bc }

  condition:
    any of them
}