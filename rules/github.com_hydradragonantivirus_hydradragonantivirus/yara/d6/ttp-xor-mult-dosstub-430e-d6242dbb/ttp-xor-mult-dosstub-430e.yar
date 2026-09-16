rule TTP_XOR_MULT_DOSStub_430e {
  strings:
    $key_430e = { 17 66 [2] 63 7e [2] 24 7c [2] 63 6d [2] 2d 61 [2] 21 6b [2] 36 60 [2] 2d 2e [2] 10 }

  condition:
    any of them
}