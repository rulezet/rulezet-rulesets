rule TTP_XOR_MULT_DOSStub_7e37 {
  strings:
    $key_7e37 = { 2a 5f [2] 5e 47 [2] 19 45 [2] 5e 54 [2] 10 58 [2] 1c 52 [2] 0b 59 [2] 10 17 [2] 2d }

  condition:
    any of them
}