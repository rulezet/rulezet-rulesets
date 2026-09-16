rule TTP_XOR_MULT_DOSStub_e57e {
  strings:
    $key_e57e = { b1 16 [2] c5 0e [2] 82 0c [2] c5 1d [2] 8b 11 [2] 87 1b [2] 90 10 [2] 8b 5e [2] b6 }

  condition:
    any of them
}