rule TTP_XOR_MULT_DOSStub_301e {
  strings:
    $key_301e = { 64 76 [2] 10 6e [2] 57 6c [2] 10 7d [2] 5e 71 [2] 52 7b [2] 45 70 [2] 5e 3e [2] 63 }

  condition:
    any of them
}