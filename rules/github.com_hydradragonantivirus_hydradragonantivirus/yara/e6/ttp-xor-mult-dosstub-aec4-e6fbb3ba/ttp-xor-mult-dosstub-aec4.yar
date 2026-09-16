rule TTP_XOR_MULT_DOSStub_aec4 {
  strings:
    $key_aec4 = { fa ac [2] 8e b4 [2] c9 b6 [2] 8e a7 [2] c0 ab [2] cc a1 [2] db aa [2] c0 e4 [2] fd }

  condition:
    any of them
}