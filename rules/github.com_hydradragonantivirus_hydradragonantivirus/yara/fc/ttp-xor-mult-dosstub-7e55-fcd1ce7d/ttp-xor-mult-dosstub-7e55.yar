rule TTP_XOR_MULT_DOSStub_7e55 {
  strings:
    $key_7e55 = { 2a 3d [2] 5e 25 [2] 19 27 [2] 5e 36 [2] 10 3a [2] 1c 30 [2] 0b 3b [2] 10 75 [2] 2d }

  condition:
    any of them
}