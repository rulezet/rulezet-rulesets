rule TTP_XOR_MULT_DOSStub_3c1e {
  strings:
    $key_3c1e = { 68 76 [2] 1c 6e [2] 5b 6c [2] 1c 7d [2] 52 71 [2] 5e 7b [2] 49 70 [2] 52 3e [2] 6f }

  condition:
    any of them
}