rule TTP_XOR_MULT_DOSStub_6545 {
  strings:
    $key_6545 = { 31 2d [2] 45 35 [2] 02 37 [2] 45 26 [2] 0b 2a [2] 07 20 [2] 10 2b [2] 0b 65 [2] 36 }

  condition:
    any of them
}