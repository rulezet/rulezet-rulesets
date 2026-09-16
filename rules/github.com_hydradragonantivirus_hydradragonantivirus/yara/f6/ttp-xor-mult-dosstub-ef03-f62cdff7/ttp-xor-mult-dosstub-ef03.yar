rule TTP_XOR_MULT_DOSStub_ef03 {
  strings:
    $key_ef03 = { bb 6b [2] cf 73 [2] 88 71 [2] cf 60 [2] 81 6c [2] 8d 66 [2] 9a 6d [2] 81 23 [2] bc }

  condition:
    any of them
}