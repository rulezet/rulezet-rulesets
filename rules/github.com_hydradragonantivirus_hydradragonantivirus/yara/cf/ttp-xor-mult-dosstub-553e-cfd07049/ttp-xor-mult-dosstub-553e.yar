rule TTP_XOR_MULT_DOSStub_553e {
  strings:
    $key_553e = { 01 56 [2] 75 4e [2] 32 4c [2] 75 5d [2] 3b 51 [2] 37 5b [2] 20 50 [2] 3b 1e [2] 06 }

  condition:
    any of them
}