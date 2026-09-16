rule TTP_XOR_MULT_DOSStub_1e74 {
  strings:
    $key_1e74 = { 4a 1c [2] 3e 04 [2] 79 06 [2] 3e 17 [2] 70 1b [2] 7c 11 [2] 6b 1a [2] 70 54 [2] 4d }

  condition:
    any of them
}