rule TTP_XOR_MULT_DOSStub_412e {
  strings:
    $key_412e = { 15 46 [2] 61 5e [2] 26 5c [2] 61 4d [2] 2f 41 [2] 23 4b [2] 34 40 [2] 2f 0e [2] 12 }

  condition:
    any of them
}