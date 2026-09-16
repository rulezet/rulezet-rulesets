rule TTP_XOR_MULT_DOSStub_fb9d {
  strings:
    $key_fb9d = { af f5 [2] db ed [2] 9c ef [2] db fe [2] 95 f2 [2] 99 f8 [2] 8e f3 [2] 95 bd [2] a8 }

  condition:
    any of them
}