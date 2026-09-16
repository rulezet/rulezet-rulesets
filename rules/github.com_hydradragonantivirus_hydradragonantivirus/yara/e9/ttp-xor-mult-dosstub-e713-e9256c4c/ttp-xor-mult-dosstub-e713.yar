rule TTP_XOR_MULT_DOSStub_e713 {
  strings:
    $key_e713 = { b3 7b [2] c7 63 [2] 80 61 [2] c7 70 [2] 89 7c [2] 85 76 [2] 92 7d [2] 89 33 [2] b4 }

  condition:
    any of them
}