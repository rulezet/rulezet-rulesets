rule TTP_XOR_MULT_DOSStub_e61f {
  strings:
    $key_e61f = { b2 77 [2] c6 6f [2] 81 6d [2] c6 7c [2] 88 70 [2] 84 7a [2] 93 71 [2] 88 3f [2] b5 }

  condition:
    any of them
}