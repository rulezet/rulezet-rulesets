rule TTP_XOR_MULT_DOSStub_372e {
  strings:
    $key_372e = { 63 46 [2] 17 5e [2] 50 5c [2] 17 4d [2] 59 41 [2] 55 4b [2] 42 40 [2] 59 0e [2] 64 }

  condition:
    any of them
}