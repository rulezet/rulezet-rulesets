rule TTP_XOR_MULT_DOSStub_4d0e {
  strings:
    $key_4d0e = { 19 66 [2] 6d 7e [2] 2a 7c [2] 6d 6d [2] 23 61 [2] 2f 6b [2] 38 60 [2] 23 2e [2] 1e }

  condition:
    any of them
}