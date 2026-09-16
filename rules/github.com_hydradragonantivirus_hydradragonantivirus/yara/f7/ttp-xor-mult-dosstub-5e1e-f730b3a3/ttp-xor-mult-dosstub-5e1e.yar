rule TTP_XOR_MULT_DOSStub_5e1e {
  strings:
    $key_5e1e = { 0a 76 [2] 7e 6e [2] 39 6c [2] 7e 7d [2] 30 71 [2] 3c 7b [2] 2b 70 [2] 30 3e [2] 0d }

  condition:
    any of them
}