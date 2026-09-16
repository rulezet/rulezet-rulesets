rule TTP_XOR_MULT_DOSStub_0e16 {
  strings:
    $key_0e16 = { 5a 7e [2] 2e 66 [2] 69 64 [2] 2e 75 [2] 60 79 [2] 6c 73 [2] 7b 78 [2] 60 36 [2] 5d }

  condition:
    any of them
}