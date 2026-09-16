rule TTP_XOR_MULT_DOSStub_1e18 {
  strings:
    $key_1e18 = { 4a 70 [2] 3e 68 [2] 79 6a [2] 3e 7b [2] 70 77 [2] 7c 7d [2] 6b 76 [2] 70 38 [2] 4d }

  condition:
    any of them
}