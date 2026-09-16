rule TTP_XOR_MULT_DOSStub_5d24 {
  strings:
    $key_5d24 = { 09 4c [2] 7d 54 [2] 3a 56 [2] 7d 47 [2] 33 4b [2] 3f 41 [2] 28 4a [2] 33 04 [2] 0e }

  condition:
    any of them
}