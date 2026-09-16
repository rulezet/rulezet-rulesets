rule TTP_XOR_MULT_DOSStub_7e08 {
  strings:
    $key_7e08 = { 2a 60 [2] 5e 78 [2] 19 7a [2] 5e 6b [2] 10 67 [2] 1c 6d [2] 0b 66 [2] 10 28 [2] 2d }

  condition:
    any of them
}