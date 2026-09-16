rule TTP_XOR_MULT_DOSStub_7e13 {
  strings:
    $key_7e13 = { 2a 7b [2] 5e 63 [2] 19 61 [2] 5e 70 [2] 10 7c [2] 1c 76 [2] 0b 7d [2] 10 33 [2] 2d }

  condition:
    any of them
}