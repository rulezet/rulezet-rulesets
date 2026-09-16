rule TTP_XOR_MULT_DOSStub_7a74 {
  strings:
    $key_7a74 = { 2e 1c [2] 5a 04 [2] 1d 06 [2] 5a 17 [2] 14 1b [2] 18 11 [2] 0f 1a [2] 14 54 [2] 29 }

  condition:
    any of them
}