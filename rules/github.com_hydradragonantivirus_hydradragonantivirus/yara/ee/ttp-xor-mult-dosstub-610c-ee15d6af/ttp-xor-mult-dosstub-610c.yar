rule TTP_XOR_MULT_DOSStub_610c {
  strings:
    $key_610c = { 35 64 [2] 41 7c [2] 06 7e [2] 41 6f [2] 0f 63 [2] 03 69 [2] 14 62 [2] 0f 2c [2] 32 }

  condition:
    any of them
}