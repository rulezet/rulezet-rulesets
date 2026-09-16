rule TTP_XOR_MULT_DOSStub_7e44 {
  strings:
    $key_7e44 = { 2a 2c [2] 5e 34 [2] 19 36 [2] 5e 27 [2] 10 2b [2] 1c 21 [2] 0b 2a [2] 10 64 [2] 2d }

  condition:
    any of them
}