rule TTP_XOR_MULT_DOSStub_6c0c {
  strings:
    $key_6c0c = { 38 64 [2] 4c 7c [2] 0b 7e [2] 4c 6f [2] 02 63 [2] 0e 69 [2] 19 62 [2] 02 2c [2] 3f }

  condition:
    any of them
}