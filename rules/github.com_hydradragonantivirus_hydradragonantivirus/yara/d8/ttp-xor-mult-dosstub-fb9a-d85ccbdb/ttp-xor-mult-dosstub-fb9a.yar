rule TTP_XOR_MULT_DOSStub_fb9a {
  strings:
    $key_fb9a = { af f2 [2] db ea [2] 9c e8 [2] db f9 [2] 95 f5 [2] 99 ff [2] 8e f4 [2] 95 ba [2] a8 }

  condition:
    any of them
}