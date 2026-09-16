rule TTP_XOR_MULT_DOSStub_5e54 {
  strings:
    $key_5e54 = { 0a 3c [2] 7e 24 [2] 39 26 [2] 7e 37 [2] 30 3b [2] 3c 31 [2] 2b 3a [2] 30 74 [2] 0d }

  condition:
    any of them
}