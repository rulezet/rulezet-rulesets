rule TTP_XOR_MULT_DOSStub_2c2b {
  strings:
    $key_2c2b = { 78 43 [2] 0c 5b [2] 4b 59 [2] 0c 48 [2] 42 44 [2] 4e 4e [2] 59 45 [2] 42 0b [2] 7f }

  condition:
    any of them
}