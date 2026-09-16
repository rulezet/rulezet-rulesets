rule TTP_XOR_MULT_DOSStub_0875 {
  strings:
    $key_0875 = { 5c 1d [2] 28 05 [2] 6f 07 [2] 28 16 [2] 66 1a [2] 6a 10 [2] 7d 1b [2] 66 55 [2] 5b }

  condition:
    any of them
}