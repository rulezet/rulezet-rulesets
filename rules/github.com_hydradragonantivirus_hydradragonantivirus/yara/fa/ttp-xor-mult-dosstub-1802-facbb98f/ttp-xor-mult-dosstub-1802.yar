rule TTP_XOR_MULT_DOSStub_1802 {
  strings:
    $key_1802 = { 4c 6a [2] 38 72 [2] 7f 70 [2] 38 61 [2] 76 6d [2] 7a 67 [2] 6d 6c [2] 76 22 [2] 4b }

  condition:
    any of them
}