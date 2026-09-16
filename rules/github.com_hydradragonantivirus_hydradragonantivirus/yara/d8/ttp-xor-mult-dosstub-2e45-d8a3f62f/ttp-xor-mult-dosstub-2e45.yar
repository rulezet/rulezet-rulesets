rule TTP_XOR_MULT_DOSStub_2e45 {
  strings:
    $key_2e45 = { 7a 2d [2] 0e 35 [2] 49 37 [2] 0e 26 [2] 40 2a [2] 4c 20 [2] 5b 2b [2] 40 65 [2] 7d }

  condition:
    any of them
}