rule TTP_XOR_MULT_DOSStub_6c3e {
  strings:
    $key_6c3e = { 38 56 [2] 4c 4e [2] 0b 4c [2] 4c 5d [2] 02 51 [2] 0e 5b [2] 19 50 [2] 02 1e [2] 3f }

  condition:
    any of them
}