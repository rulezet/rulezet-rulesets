rule TTP_XOR_MULT_DOSStub_5e44 {
  strings:
    $key_5e44 = { 0a 2c [2] 7e 34 [2] 39 36 [2] 7e 27 [2] 30 2b [2] 3c 21 [2] 2b 2a [2] 30 64 [2] 0d }

  condition:
    any of them
}