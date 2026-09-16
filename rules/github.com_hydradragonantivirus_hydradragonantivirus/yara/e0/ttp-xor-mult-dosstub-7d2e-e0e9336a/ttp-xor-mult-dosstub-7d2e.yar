rule TTP_XOR_MULT_DOSStub_7d2e {
  strings:
    $key_7d2e = { 29 46 [2] 5d 5e [2] 1a 5c [2] 5d 4d [2] 13 41 [2] 1f 4b [2] 08 40 [2] 13 0e [2] 2e }

  condition:
    any of them
}