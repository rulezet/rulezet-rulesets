rule TTP_XOR_MULT_DOSStub_5ee6 {
  strings:
    $key_5ee6 = { 0a 8e [2] 7e 96 [2] 39 94 [2] 7e 85 [2] 30 89 [2] 3c 83 [2] 2b 88 [2] 30 c6 [2] 0d }

  condition:
    any of them
}