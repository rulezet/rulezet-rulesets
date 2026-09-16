rule TTP_XOR_MULT_DOSStub_3c0e {
  strings:
    $key_3c0e = { 68 66 [2] 1c 7e [2] 5b 7c [2] 1c 6d [2] 52 61 [2] 5e 6b [2] 49 60 [2] 52 2e [2] 6f }

  condition:
    any of them
}