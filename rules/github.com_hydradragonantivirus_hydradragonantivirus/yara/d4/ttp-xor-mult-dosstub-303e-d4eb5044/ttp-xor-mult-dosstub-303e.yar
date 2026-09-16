rule TTP_XOR_MULT_DOSStub_303e {
  strings:
    $key_303e = { 64 56 [2] 10 4e [2] 57 4c [2] 10 5d [2] 5e 51 [2] 52 5b [2] 45 50 [2] 5e 1e [2] 63 }

  condition:
    any of them
}