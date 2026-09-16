rule TTP_XOR_MULT_DOSStub_2e35 {
  strings:
    $key_2e35 = { 7a 5d [2] 0e 45 [2] 49 47 [2] 0e 56 [2] 40 5a [2] 4c 50 [2] 5b 5b [2] 40 15 [2] 7d }

  condition:
    any of them
}