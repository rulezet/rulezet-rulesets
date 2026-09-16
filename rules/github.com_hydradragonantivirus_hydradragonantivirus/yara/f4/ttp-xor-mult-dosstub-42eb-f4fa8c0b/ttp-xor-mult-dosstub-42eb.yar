rule TTP_XOR_MULT_DOSStub_42eb {
  strings:
    $key_42eb = { 16 83 [2] 62 9b [2] 25 99 [2] 62 88 [2] 2c 84 [2] 20 8e [2] 37 85 [2] 2c cb [2] 11 }

  condition:
    any of them
}