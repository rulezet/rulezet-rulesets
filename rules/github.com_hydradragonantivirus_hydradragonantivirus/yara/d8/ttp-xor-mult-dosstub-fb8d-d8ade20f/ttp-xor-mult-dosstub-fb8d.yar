rule TTP_XOR_MULT_DOSStub_fb8d {
  strings:
    $key_fb8d = { af e5 [2] db fd [2] 9c ff [2] db ee [2] 95 e2 [2] 99 e8 [2] 8e e3 [2] 95 ad [2] a8 }

  condition:
    any of them
}