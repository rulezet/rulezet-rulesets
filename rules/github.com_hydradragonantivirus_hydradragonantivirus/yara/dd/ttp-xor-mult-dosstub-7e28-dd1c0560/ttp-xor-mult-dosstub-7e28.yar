rule TTP_XOR_MULT_DOSStub_7e28 {
  strings:
    $key_7e28 = { 2a 40 [2] 5e 58 [2] 19 5a [2] 5e 4b [2] 10 47 [2] 1c 4d [2] 0b 46 [2] 10 08 [2] 2d }

  condition:
    any of them
}