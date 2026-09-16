rule TTP_XOR_MULT_DOSStub_f998 {
  strings:
    $key_f998 = { ad f0 [2] d9 e8 [2] 9e ea [2] d9 fb [2] 97 f7 [2] 9b fd [2] 8c f6 [2] 97 b8 [2] aa }

  condition:
    any of them
}