rule TTP_XOR_MULT_DOSStub_2e0e {
  strings:
    $key_2e0e = { 7a 66 [2] 0e 7e [2] 49 7c [2] 0e 6d [2] 40 61 [2] 4c 6b [2] 5b 60 [2] 40 2e [2] 7d }

  condition:
    any of them
}