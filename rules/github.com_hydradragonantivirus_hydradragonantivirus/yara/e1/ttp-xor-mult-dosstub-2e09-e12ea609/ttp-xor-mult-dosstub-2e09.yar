rule TTP_XOR_MULT_DOSStub_2e09 {
  strings:
    $key_2e09 = { 7a 61 [2] 0e 79 [2] 49 7b [2] 0e 6a [2] 40 66 [2] 4c 6c [2] 5b 67 [2] 40 29 [2] 7d }

  condition:
    any of them
}