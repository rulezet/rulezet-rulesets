rule TTP_XOR_MULT_DOSStub_2c3e {
  strings:
    $key_2c3e = { 78 56 [2] 0c 4e [2] 4b 4c [2] 0c 5d [2] 42 51 [2] 4e 5b [2] 59 50 [2] 42 1e [2] 7f }

  condition:
    any of them
}