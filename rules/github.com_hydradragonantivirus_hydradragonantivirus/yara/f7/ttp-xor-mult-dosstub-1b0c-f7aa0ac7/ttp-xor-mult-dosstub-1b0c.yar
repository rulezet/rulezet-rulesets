rule TTP_XOR_MULT_DOSStub_1b0c {
  strings:
    $key_1b0c = { 4f 64 [2] 3b 7c [2] 7c 7e [2] 3b 6f [2] 75 63 [2] 79 69 [2] 6e 62 [2] 75 2c [2] 48 }

  condition:
    any of them
}