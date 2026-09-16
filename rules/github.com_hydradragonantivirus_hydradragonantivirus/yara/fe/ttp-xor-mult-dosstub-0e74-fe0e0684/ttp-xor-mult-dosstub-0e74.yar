rule TTP_XOR_MULT_DOSStub_0e74 {
  strings:
    $key_0e74 = { 5a 1c [2] 2e 04 [2] 69 06 [2] 2e 17 [2] 60 1b [2] 6c 11 [2] 7b 1a [2] 60 54 [2] 5d }

  condition:
    any of them
}