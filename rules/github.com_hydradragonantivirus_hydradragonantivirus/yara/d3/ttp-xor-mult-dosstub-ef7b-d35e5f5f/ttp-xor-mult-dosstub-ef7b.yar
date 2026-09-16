rule TTP_XOR_MULT_DOSStub_ef7b {
  strings:
    $key_ef7b = { bb 13 [2] cf 0b [2] 88 09 [2] cf 18 [2] 81 14 [2] 8d 1e [2] 9a 15 [2] 81 5b [2] bc }

  condition:
    any of them
}