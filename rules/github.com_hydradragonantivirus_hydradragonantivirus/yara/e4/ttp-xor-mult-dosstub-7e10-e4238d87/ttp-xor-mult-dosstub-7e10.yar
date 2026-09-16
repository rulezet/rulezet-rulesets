rule TTP_XOR_MULT_DOSStub_7e10 {
  strings:
    $key_7e10 = { 2a 78 [2] 5e 60 [2] 19 62 [2] 5e 73 [2] 10 7f [2] 1c 75 [2] 0b 7e [2] 10 30 [2] 2d }

  condition:
    any of them
}