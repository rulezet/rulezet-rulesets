rule TTP_XOR_MULT_DOSStub_cd8d {
  strings:
    $key_cd8d = { 99 e5 [2] ed fd [2] aa ff [2] ed ee [2] a3 e2 [2] af e8 [2] b8 e3 [2] a3 ad [2] 9e }

  condition:
    any of them
}