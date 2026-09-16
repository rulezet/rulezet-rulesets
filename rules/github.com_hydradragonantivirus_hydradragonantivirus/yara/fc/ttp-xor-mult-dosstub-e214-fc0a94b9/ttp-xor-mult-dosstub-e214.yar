rule TTP_XOR_MULT_DOSStub_e214 {
  strings:
    $key_e214 = { b6 7c [2] c2 64 [2] 85 66 [2] c2 77 [2] 8c 7b [2] 80 71 [2] 97 7a [2] 8c 34 [2] b1 }

  condition:
    any of them
}