rule TTP_XOR_MULT_DOSStub_ef2e {
  strings:
    $key_ef2e = { bb 46 [2] cf 5e [2] 88 5c [2] cf 4d [2] 81 41 [2] 8d 4b [2] 9a 40 [2] 81 0e [2] bc }

  condition:
    any of them
}