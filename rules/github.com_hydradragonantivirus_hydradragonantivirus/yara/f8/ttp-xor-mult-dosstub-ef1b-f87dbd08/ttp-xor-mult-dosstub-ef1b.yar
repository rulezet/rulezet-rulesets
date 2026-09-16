rule TTP_XOR_MULT_DOSStub_ef1b {
  strings:
    $key_ef1b = { bb 73 [2] cf 6b [2] 88 69 [2] cf 78 [2] 81 74 [2] 8d 7e [2] 9a 75 [2] 81 3b [2] bc }

  condition:
    any of them
}