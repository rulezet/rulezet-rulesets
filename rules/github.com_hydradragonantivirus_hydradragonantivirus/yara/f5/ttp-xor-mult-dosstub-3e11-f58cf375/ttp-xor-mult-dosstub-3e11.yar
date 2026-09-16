rule TTP_XOR_MULT_DOSStub_3e11 {
  strings:
    $key_3e11 = { 6a 79 [2] 1e 61 [2] 59 63 [2] 1e 72 [2] 50 7e [2] 5c 74 [2] 4b 7f [2] 50 31 [2] 6d }

  condition:
    any of them
}