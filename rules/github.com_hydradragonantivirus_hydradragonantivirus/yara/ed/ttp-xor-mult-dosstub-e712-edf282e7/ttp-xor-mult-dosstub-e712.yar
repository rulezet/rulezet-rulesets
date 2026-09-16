rule TTP_XOR_MULT_DOSStub_e712 {
  strings:
    $key_e712 = { b3 7a [2] c7 62 [2] 80 60 [2] c7 71 [2] 89 7d [2] 85 77 [2] 92 7c [2] 89 32 [2] b4 }

  condition:
    any of them
}