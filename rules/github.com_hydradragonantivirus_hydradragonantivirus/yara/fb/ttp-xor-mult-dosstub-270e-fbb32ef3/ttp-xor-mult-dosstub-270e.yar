rule TTP_XOR_MULT_DOSStub_270e {
  strings:
    $key_270e = { 73 66 [2] 07 7e [2] 40 7c [2] 07 6d [2] 49 61 [2] 45 6b [2] 52 60 [2] 49 2e [2] 74 }

  condition:
    any of them
}