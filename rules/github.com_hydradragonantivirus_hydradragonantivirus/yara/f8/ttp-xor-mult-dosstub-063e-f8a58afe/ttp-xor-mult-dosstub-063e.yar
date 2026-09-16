rule TTP_XOR_MULT_DOSStub_063e {
  strings:
    $key_063e = { 52 56 [2] 26 4e [2] 61 4c [2] 26 5d [2] 68 51 [2] 64 5b [2] 73 50 [2] 68 1e [2] 55 }

  condition:
    any of them
}