rule TTP_XOR_MULT_DOSStub_722e {
  strings:
    $key_722e = { 26 46 [2] 52 5e [2] 15 5c [2] 52 4d [2] 1c 41 [2] 10 4b [2] 07 40 [2] 1c 0e [2] 21 }

  condition:
    any of them
}