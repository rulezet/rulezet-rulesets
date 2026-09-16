rule TTP_XOR_MULT_DOSStub_7ef1 {
  strings:
    $key_7ef1 = { 2a 99 [2] 5e 81 [2] 19 83 [2] 5e 92 [2] 10 9e [2] 1c 94 [2] 0b 9f [2] 10 d1 [2] 2d }

  condition:
    any of them
}