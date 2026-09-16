rule TTP_XOR_MULT_DOSStub_ef7c {
  strings:
    $key_ef7c = { bb 14 [2] cf 0c [2] 88 0e [2] cf 1f [2] 81 13 [2] 8d 19 [2] 9a 12 [2] 81 5c [2] bc }

  condition:
    any of them
}