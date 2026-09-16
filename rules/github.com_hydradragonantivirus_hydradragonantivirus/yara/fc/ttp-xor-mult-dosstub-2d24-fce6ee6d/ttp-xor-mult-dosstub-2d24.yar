rule TTP_XOR_MULT_DOSStub_2d24 {
  strings:
    $key_2d24 = { 79 4c [2] 0d 54 [2] 4a 56 [2] 0d 47 [2] 43 4b [2] 4f 41 [2] 58 4a [2] 43 04 [2] 7e }

  condition:
    any of them
}