rule TTP_XOR_MULT_DOSStub_7b2e {
  strings:
    $key_7b2e = { 2f 46 [2] 5b 5e [2] 1c 5c [2] 5b 4d [2] 15 41 [2] 19 4b [2] 0e 40 [2] 15 0e [2] 28 }

  condition:
    any of them
}