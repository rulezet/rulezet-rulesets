rule TTP_XOR_MULT_DOSStub_5e0e {
  strings:
    $key_5e0e = { 0a 66 [2] 7e 7e [2] 39 7c [2] 7e 6d [2] 30 61 [2] 3c 6b [2] 2b 60 [2] 30 2e [2] 0d }

  condition:
    any of them
}