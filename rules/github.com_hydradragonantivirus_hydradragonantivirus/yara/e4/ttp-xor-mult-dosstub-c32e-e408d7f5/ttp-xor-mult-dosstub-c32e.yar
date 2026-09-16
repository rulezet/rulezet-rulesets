rule TTP_XOR_MULT_DOSStub_c32e {
  strings:
    $key_c32e = { 97 46 [2] e3 5e [2] a4 5c [2] e3 4d [2] ad 41 [2] a1 4b [2] b6 40 [2] ad 0e [2] 90 }

  condition:
    any of them
}