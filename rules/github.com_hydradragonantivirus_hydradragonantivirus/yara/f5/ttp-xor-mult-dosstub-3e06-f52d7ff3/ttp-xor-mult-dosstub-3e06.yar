rule TTP_XOR_MULT_DOSStub_3e06 {
  strings:
    $key_3e06 = { 6a 6e [2] 1e 76 [2] 59 74 [2] 1e 65 [2] 50 69 [2] 5c 63 [2] 4b 68 [2] 50 26 [2] 6d }

  condition:
    any of them
}