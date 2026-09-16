rule TTP_XOR_MULT_DOSStub_ef4a {
  strings:
    $key_ef4a = { bb 22 [2] cf 3a [2] 88 38 [2] cf 29 [2] 81 25 [2] 8d 2f [2] 9a 24 [2] 81 6a [2] bc }

  condition:
    any of them
}