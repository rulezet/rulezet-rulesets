rule TTP_XOR_MULT_DOSStub_441b {
  strings:
    $key_441b = { 10 73 [2] 64 6b [2] 23 69 [2] 64 78 [2] 2a 74 [2] 26 7e [2] 31 75 [2] 2a 3b [2] 17 }

  condition:
    any of them
}