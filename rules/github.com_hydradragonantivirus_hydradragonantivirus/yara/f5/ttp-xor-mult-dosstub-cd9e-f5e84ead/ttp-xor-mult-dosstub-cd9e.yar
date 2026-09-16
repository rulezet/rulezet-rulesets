rule TTP_XOR_MULT_DOSStub_cd9e {
  strings:
    $key_cd9e = { 99 f6 [2] ed ee [2] aa ec [2] ed fd [2] a3 f1 [2] af fb [2] b8 f0 [2] a3 be [2] 9e }

  condition:
    any of them
}