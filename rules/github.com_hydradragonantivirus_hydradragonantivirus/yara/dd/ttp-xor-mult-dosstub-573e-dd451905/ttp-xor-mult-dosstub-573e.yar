rule TTP_XOR_MULT_DOSStub_573e {
  strings:
    $key_573e = { 03 56 [2] 77 4e [2] 30 4c [2] 77 5d [2] 39 51 [2] 35 5b [2] 22 50 [2] 39 1e [2] 04 }

  condition:
    any of them
}