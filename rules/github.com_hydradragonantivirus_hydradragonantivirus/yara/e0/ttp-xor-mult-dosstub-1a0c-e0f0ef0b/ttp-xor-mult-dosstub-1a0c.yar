rule TTP_XOR_MULT_DOSStub_1a0c {
  strings:
    $key_1a0c = { 4e 64 [2] 3a 7c [2] 7d 7e [2] 3a 6f [2] 74 63 [2] 78 69 [2] 6f 62 [2] 74 2c [2] 49 }

  condition:
    any of them
}