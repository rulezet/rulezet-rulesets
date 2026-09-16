rule TTP_XOR_MULT_DOSStub_c00e {
  strings:
    $key_c00e = { 94 66 [2] e0 7e [2] a7 7c [2] e0 6d [2] ae 61 [2] a2 6b [2] b5 60 [2] ae 2e [2] 93 }

  condition:
    any of them
}