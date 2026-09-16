rule TTP_XOR_MULT_DOSStub_640c {
  strings:
    $key_640c = { 30 64 [2] 44 7c [2] 03 7e [2] 44 6f [2] 0a 63 [2] 06 69 [2] 11 62 [2] 0a 2c [2] 37 }

  condition:
    any of them
}