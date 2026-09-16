rule TTP_XOR_MULT_DOSStub_7d75 {
  strings:
    $key_7d75 = { 29 1d [2] 5d 05 [2] 1a 07 [2] 5d 16 [2] 13 1a [2] 1f 10 [2] 08 1b [2] 13 55 [2] 2e }

  condition:
    any of them
}