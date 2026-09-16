rule TTP_XOR_MULT_DOSStub_010e {
  strings:
    $key_010e = { 55 66 [2] 21 7e [2] 66 7c [2] 21 6d [2] 6f 61 [2] 63 6b [2] 74 60 [2] 6f 2e [2] 52 }

  condition:
    any of them
}