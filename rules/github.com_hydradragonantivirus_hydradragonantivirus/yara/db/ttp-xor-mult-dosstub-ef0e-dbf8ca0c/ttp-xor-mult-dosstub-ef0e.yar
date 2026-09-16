rule TTP_XOR_MULT_DOSStub_ef0e {
  strings:
    $key_ef0e = { bb 66 [2] cf 7e [2] 88 7c [2] cf 6d [2] 81 61 [2] 8d 6b [2] 9a 60 [2] 81 2e [2] bc }

  condition:
    any of them
}