rule TTP_XOR_MULT_DOSStub_ef5e {
  strings:
    $key_ef5e = { bb 36 [2] cf 2e [2] 88 2c [2] cf 3d [2] 81 31 [2] 8d 3b [2] 9a 30 [2] 81 7e [2] bc }

  condition:
    any of them
}