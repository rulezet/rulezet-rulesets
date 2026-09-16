rule TTP_XOR_MULT_DOSStub_ef23 {
  strings:
    $key_ef23 = { bb 4b [2] cf 53 [2] 88 51 [2] cf 40 [2] 81 4c [2] 8d 46 [2] 9a 4d [2] 81 03 [2] bc }

  condition:
    any of them
}