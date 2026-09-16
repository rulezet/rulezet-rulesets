rule TTP_XOR_MULT_DOSStub_5d0e {
  strings:
    $key_5d0e = { 09 66 [2] 7d 7e [2] 3a 7c [2] 7d 6d [2] 33 61 [2] 3f 6b [2] 28 60 [2] 33 2e [2] 0e }

  condition:
    any of them
}