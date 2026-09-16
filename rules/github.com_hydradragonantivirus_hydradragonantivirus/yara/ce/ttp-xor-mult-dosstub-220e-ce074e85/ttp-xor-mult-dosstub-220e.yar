rule TTP_XOR_MULT_DOSStub_220e {
  strings:
    $key_220e = { 76 66 [2] 02 7e [2] 45 7c [2] 02 6d [2] 4c 61 [2] 40 6b [2] 57 60 [2] 4c 2e [2] 71 }

  condition:
    any of them
}