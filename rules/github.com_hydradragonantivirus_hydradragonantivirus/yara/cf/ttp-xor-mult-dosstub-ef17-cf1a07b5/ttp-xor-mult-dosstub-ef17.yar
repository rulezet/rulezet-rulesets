rule TTP_XOR_MULT_DOSStub_ef17 {
  strings:
    $key_ef17 = { bb 7f [2] cf 67 [2] 88 65 [2] cf 74 [2] 81 78 [2] 8d 72 [2] 9a 79 [2] 81 37 [2] bc }

  condition:
    any of them
}