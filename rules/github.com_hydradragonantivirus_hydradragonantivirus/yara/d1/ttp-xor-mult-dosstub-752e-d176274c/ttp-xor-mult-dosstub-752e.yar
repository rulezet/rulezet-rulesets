rule TTP_XOR_MULT_DOSStub_752e {
  strings:
    $key_752e = { 21 46 [2] 55 5e [2] 12 5c [2] 55 4d [2] 1b 41 [2] 17 4b [2] 00 40 [2] 1b 0e [2] 26 }

  condition:
    any of them
}