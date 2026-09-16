rule TTP_XOR_MULT_DOSStub_ea9a {
  strings:
    $key_ea9a = { be f2 [2] ca ea [2] 8d e8 [2] ca f9 [2] 84 f5 [2] 88 ff [2] 9f f4 [2] 84 ba [2] b9 }

  condition:
    any of them
}