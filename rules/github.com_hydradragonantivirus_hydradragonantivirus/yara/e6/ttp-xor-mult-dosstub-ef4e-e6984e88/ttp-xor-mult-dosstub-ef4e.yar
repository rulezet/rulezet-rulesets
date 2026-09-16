rule TTP_XOR_MULT_DOSStub_ef4e {
  strings:
    $key_ef4e = { bb 26 [2] cf 3e [2] 88 3c [2] cf 2d [2] 81 21 [2] 8d 2b [2] 9a 20 [2] 81 6e [2] bc }

  condition:
    any of them
}