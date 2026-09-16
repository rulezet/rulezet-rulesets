rule TTP_XOR_MULT_DOSStub_2e39 {
  strings:
    $key_2e39 = { 7a 51 [2] 0e 49 [2] 49 4b [2] 0e 5a [2] 40 56 [2] 4c 5c [2] 5b 57 [2] 40 19 [2] 7d }

  condition:
    any of them
}