rule TTP_XOR_MULT_DOSStub_4d24 {
  strings:
    $key_4d24 = { 19 4c [2] 6d 54 [2] 2a 56 [2] 6d 47 [2] 23 4b [2] 2f 41 [2] 38 4a [2] 23 04 [2] 1e }

  condition:
    any of them
}