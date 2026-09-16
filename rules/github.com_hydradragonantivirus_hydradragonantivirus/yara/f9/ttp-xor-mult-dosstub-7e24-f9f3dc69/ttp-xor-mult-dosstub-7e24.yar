rule TTP_XOR_MULT_DOSStub_7e24 {
  strings:
    $key_7e24 = { 2a 4c [2] 5e 54 [2] 19 56 [2] 5e 47 [2] 10 4b [2] 1c 41 [2] 0b 4a [2] 10 04 [2] 2d }

  condition:
    any of them
}