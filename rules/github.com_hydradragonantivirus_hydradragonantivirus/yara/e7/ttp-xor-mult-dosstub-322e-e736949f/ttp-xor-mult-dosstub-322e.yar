rule TTP_XOR_MULT_DOSStub_322e {
  strings:
    $key_322e = { 66 46 [2] 12 5e [2] 55 5c [2] 12 4d [2] 5c 41 [2] 50 4b [2] 47 40 [2] 5c 0e [2] 61 }

  condition:
    any of them
}