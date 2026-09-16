rule TTP_XOR_MULT_DOSStub_360e {
  strings:
    $key_360e = { 62 66 [2] 16 7e [2] 51 7c [2] 16 6d [2] 58 61 [2] 54 6b [2] 43 60 [2] 58 2e [2] 65 }

  condition:
    any of them
}