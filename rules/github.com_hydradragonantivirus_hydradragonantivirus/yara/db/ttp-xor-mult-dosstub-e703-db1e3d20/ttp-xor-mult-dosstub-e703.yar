rule TTP_XOR_MULT_DOSStub_e703 {
  strings:
    $key_e703 = { b3 6b [2] c7 73 [2] 80 71 [2] c7 60 [2] 89 6c [2] 85 66 [2] 92 6d [2] 89 23 [2] b4 }

  condition:
    any of them
}