rule TTP_XOR_MULT_DOSStub_343e {
  strings:
    $key_343e = { 60 56 [2] 14 4e [2] 53 4c [2] 14 5d [2] 5a 51 [2] 56 5b [2] 41 50 [2] 5a 1e [2] 67 }

  condition:
    any of them
}