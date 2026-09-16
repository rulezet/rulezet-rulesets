rule TTP_XOR_MULT_DOSStub_2e3e {
  strings:
    $key_2e3e = { 7a 56 [2] 0e 4e [2] 49 4c [2] 0e 5d [2] 40 51 [2] 4c 5b [2] 5b 50 [2] 40 1e [2] 7d }

  condition:
    any of them
}