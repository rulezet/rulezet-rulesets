rule TTP_XOR_MULT_DOSStub_2e48 {
  strings:
    $key_2e48 = { 7a 20 [2] 0e 38 [2] 49 3a [2] 0e 2b [2] 40 27 [2] 4c 2d [2] 5b 26 [2] 40 68 [2] 7d }

  condition:
    any of them
}