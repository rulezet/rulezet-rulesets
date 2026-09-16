rule TTP_XOR_MULT_DOSStub_6543 {
  strings:
    $key_6543 = { 31 2b [2] 45 33 [2] 02 31 [2] 45 20 [2] 0b 2c [2] 07 26 [2] 10 2d [2] 0b 63 [2] 36 }

  condition:
    any of them
}