rule TTP_XOR_MULT_DOSStub_7956 {
  strings:
    $key_7956 = { 2d 3e [2] 59 26 [2] 1e 24 [2] 59 35 [2] 17 39 [2] 1b 33 [2] 0c 38 [2] 17 76 [2] 2a }

  condition:
    any of them
}