rule TTP_XOR_MULT_DOSStub_0b3e {
  strings:
    $key_0b3e = { 5f 56 [2] 2b 4e [2] 6c 4c [2] 2b 5d [2] 65 51 [2] 69 5b [2] 7e 50 [2] 65 1e [2] 58 }

  condition:
    any of them
}