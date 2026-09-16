rule TTP_XOR_MULT_DOSStub_0e01 {
  strings:
    $key_0e01 = { 5a 69 [2] 2e 71 [2] 69 73 [2] 2e 62 [2] 60 6e [2] 6c 64 [2] 7b 6f [2] 60 21 [2] 5d }

  condition:
    any of them
}