rule TTP_XOR_MULT_DOSStub_4d75 {
  strings:
    $key_4d75 = { 19 1d [2] 6d 05 [2] 2a 07 [2] 6d 16 [2] 23 1a [2] 2f 10 [2] 38 1b [2] 23 55 [2] 1e }

  condition:
    any of them
}