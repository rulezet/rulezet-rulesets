rule TTP_XOR_MULT_DOSStub_7e79 {
  strings:
    $key_7e79 = { 2a 11 [2] 5e 09 [2] 19 0b [2] 5e 1a [2] 10 16 [2] 1c 1c [2] 0b 17 [2] 10 59 [2] 2d }

  condition:
    any of them
}