rule TTP_XOR_MULT_DOSStub_7e72 {
  strings:
    $key_7e72 = { 2a 1a [2] 5e 02 [2] 19 00 [2] 5e 11 [2] 10 1d [2] 1c 17 [2] 0b 1c [2] 10 52 [2] 2d }

  condition:
    any of them
}