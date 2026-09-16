rule TTP_XOR_MULT_DOSStub_2e29 {
  strings:
    $key_2e29 = { 7a 41 [2] 0e 59 [2] 49 5b [2] 0e 4a [2] 40 46 [2] 4c 4c [2] 5b 47 [2] 40 09 [2] 7d }

  condition:
    any of them
}