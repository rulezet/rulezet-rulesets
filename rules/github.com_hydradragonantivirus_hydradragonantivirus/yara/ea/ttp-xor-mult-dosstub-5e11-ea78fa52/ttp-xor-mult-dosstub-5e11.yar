rule TTP_XOR_MULT_DOSStub_5e11 {
  strings:
    $key_5e11 = { 0a 79 [2] 7e 61 [2] 39 63 [2] 7e 72 [2] 30 7e [2] 3c 74 [2] 2b 7f [2] 30 31 [2] 0d }

  condition:
    any of them
}