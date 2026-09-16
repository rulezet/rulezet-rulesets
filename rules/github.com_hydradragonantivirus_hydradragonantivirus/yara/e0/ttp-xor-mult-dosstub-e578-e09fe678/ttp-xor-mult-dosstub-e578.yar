rule TTP_XOR_MULT_DOSStub_e578 {
  strings:
    $key_e578 = { b1 10 [2] c5 08 [2] 82 0a [2] c5 1b [2] 8b 17 [2] 87 1d [2] 90 16 [2] 8b 58 [2] b6 }

  condition:
    any of them
}