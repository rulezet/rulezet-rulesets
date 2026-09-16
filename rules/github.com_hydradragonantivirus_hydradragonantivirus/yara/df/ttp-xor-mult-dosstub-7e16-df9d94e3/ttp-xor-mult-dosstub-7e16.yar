rule TTP_XOR_MULT_DOSStub_7e16 {
  strings:
    $key_7e16 = { 2a 7e [2] 5e 66 [2] 19 64 [2] 5e 75 [2] 10 79 [2] 1c 73 [2] 0b 78 [2] 10 36 [2] 2d }

  condition:
    any of them
}