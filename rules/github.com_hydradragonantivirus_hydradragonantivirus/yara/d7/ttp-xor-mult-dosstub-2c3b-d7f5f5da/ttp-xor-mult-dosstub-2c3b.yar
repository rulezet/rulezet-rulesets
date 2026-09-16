rule TTP_XOR_MULT_DOSStub_2c3b {
  strings:
    $key_2c3b = { 78 53 [2] 0c 4b [2] 4b 49 [2] 0c 58 [2] 42 54 [2] 4e 5e [2] 59 55 [2] 42 1b [2] 7f }

  condition:
    any of them
}