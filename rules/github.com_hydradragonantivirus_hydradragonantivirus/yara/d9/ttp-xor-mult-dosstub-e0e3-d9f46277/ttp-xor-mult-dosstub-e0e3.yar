rule TTP_XOR_MULT_DOSStub_e0e3 {
  strings:
    $key_e0e3 = { b4 8b [2] c0 93 [2] 87 91 [2] c0 80 [2] 8e 8c [2] 82 86 [2] 95 8d [2] 8e c3 [2] b3 }

  condition:
    any of them
}