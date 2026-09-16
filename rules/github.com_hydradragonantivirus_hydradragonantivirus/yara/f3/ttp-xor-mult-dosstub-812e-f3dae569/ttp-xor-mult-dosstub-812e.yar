rule TTP_XOR_MULT_DOSStub_812e {
  strings:
    $key_812e = { d5 46 [2] a1 5e [2] e6 5c [2] a1 4d [2] ef 41 [2] e3 4b [2] f4 40 [2] ef 0e [2] d2 }

  condition:
    any of them
}