rule TTP_XOR_MULT_DOSStub_2643 {
  strings:
    $key_2643 = { 72 2b [2] 06 33 [2] 41 31 [2] 06 20 [2] 48 2c [2] 44 26 [2] 53 2d [2] 48 63 [2] 75 }

  condition:
    any of them
}