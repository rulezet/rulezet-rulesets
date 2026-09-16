rule TTP_XOR_MULT_DOSStub_720c {
  strings:
    $key_720c = { 26 64 [2] 52 7c [2] 15 7e [2] 52 6f [2] 1c 63 [2] 10 69 [2] 07 62 [2] 1c 2c [2] 21 }

  condition:
    any of them
}