rule TTP_XOR_MULT_DOSStub_0e00 {
  strings:
    $key_0e00 = { 5a 68 [2] 2e 70 [2] 69 72 [2] 2e 63 [2] 60 6f [2] 6c 65 [2] 7b 6e [2] 60 20 [2] 5d }

  condition:
    any of them
}