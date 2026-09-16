rule TTP_XOR_MULT_DOSStub_ef01 {
  strings:
    $key_ef01 = { bb 69 [2] cf 71 [2] 88 73 [2] cf 62 [2] 81 6e [2] 8d 64 [2] 9a 6f [2] 81 21 [2] bc }

  condition:
    any of them
}