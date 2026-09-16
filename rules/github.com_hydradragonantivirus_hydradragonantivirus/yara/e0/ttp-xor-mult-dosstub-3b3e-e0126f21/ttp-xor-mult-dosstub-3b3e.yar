rule TTP_XOR_MULT_DOSStub_3b3e {
  strings:
    $key_3b3e = { 6f 56 [2] 1b 4e [2] 5c 4c [2] 1b 5d [2] 55 51 [2] 59 5b [2] 4e 50 [2] 55 1e [2] 68 }

  condition:
    any of them
}