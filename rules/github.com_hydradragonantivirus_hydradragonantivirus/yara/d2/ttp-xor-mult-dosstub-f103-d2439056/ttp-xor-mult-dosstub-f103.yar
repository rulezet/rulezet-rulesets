rule TTP_XOR_MULT_DOSStub_f103 {
  strings:
    $key_f103 = { a5 6b [2] d1 73 [2] 96 71 [2] d1 60 [2] 9f 6c [2] 93 66 [2] 84 6d [2] 9f 23 [2] a2 }

  condition:
    any of them
}