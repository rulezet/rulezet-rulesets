rule TTP_XOR_MULT_DOSStub_2c1c {
  strings:
    $key_2c1c = { 78 74 [2] 0c 6c [2] 4b 6e [2] 0c 7f [2] 42 73 [2] 4e 79 [2] 59 72 [2] 42 3c [2] 7f }

  condition:
    any of them
}