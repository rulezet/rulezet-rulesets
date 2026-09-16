rule TTP_XOR_MULT_DOSStub_2e78 {
  strings:
    $key_2e78 = { 7a 10 [2] 0e 08 [2] 49 0a [2] 0e 1b [2] 40 17 [2] 4c 1d [2] 5b 16 [2] 40 58 [2] 7d }

  condition:
    any of them
}