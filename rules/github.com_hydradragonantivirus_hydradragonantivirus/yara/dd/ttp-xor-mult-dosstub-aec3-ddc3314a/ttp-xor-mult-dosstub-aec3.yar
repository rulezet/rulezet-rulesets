rule TTP_XOR_MULT_DOSStub_aec3 {
  strings:
    $key_aec3 = { fa ab [2] 8e b3 [2] c9 b1 [2] 8e a0 [2] c0 ac [2] cc a6 [2] db ad [2] c0 e3 [2] fd }

  condition:
    any of them
}