rule TTP_XOR_MULT_DOSStub_e41e {
  strings:
    $key_e41e = { b0 76 [2] c4 6e [2] 83 6c [2] c4 7d [2] 8a 71 [2] 86 7b [2] 91 70 [2] 8a 3e [2] b7 }

  condition:
    any of them
}