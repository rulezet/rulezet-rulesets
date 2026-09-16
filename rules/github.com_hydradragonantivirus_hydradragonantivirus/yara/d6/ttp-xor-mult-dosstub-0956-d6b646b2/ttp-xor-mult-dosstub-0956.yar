rule TTP_XOR_MULT_DOSStub_0956 {
  strings:
    $key_0956 = { 5d 3e [2] 29 26 [2] 6e 24 [2] 29 35 [2] 67 39 [2] 6b 33 [2] 7c 38 [2] 67 76 [2] 5a }

  condition:
    any of them
}