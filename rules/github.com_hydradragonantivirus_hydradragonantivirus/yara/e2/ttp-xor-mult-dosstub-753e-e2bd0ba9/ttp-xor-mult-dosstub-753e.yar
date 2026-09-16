rule TTP_XOR_MULT_DOSStub_753e {
  strings:
    $key_753e = { 21 56 [2] 55 4e [2] 12 4c [2] 55 5d [2] 1b 51 [2] 17 5b [2] 00 50 [2] 1b 1e [2] 26 }

  condition:
    any of them
}