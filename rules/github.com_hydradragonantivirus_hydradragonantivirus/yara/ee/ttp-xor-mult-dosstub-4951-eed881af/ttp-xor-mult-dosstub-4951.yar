rule TTP_XOR_MULT_DOSStub_4951 {
  strings:
    $key_4951 = { 1d 39 [2] 69 21 [2] 2e 23 [2] 69 32 [2] 27 3e [2] 2b 34 [2] 3c 3f [2] 27 71 [2] 1a }

  condition:
    any of them
}