rule TTP_XOR_MULT_DOSStub_442e {
  strings:
    $key_442e = { 10 46 [2] 64 5e [2] 23 5c [2] 64 4d [2] 2a 41 [2] 26 4b [2] 31 40 [2] 2a 0e [2] 17 }

  condition:
    any of them
}