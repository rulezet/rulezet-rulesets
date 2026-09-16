rule TTP_XOR_MULT_DOSStub_3e42 {
  strings:
    $key_3e42 = { 6a 2a [2] 1e 32 [2] 59 30 [2] 1e 21 [2] 50 2d [2] 5c 27 [2] 4b 2c [2] 50 62 [2] 6d }

  condition:
    any of them
}