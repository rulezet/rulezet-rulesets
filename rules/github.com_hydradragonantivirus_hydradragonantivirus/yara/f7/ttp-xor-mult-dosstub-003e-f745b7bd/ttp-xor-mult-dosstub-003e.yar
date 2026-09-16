rule TTP_XOR_MULT_DOSStub_003e {
  strings:
    $key_003e = { 54 56 [2] 20 4e [2] 67 4c [2] 20 5d [2] 6e 51 [2] 62 5b [2] 75 50 [2] 6e 1e [2] 53 }

  condition:
    any of them
}