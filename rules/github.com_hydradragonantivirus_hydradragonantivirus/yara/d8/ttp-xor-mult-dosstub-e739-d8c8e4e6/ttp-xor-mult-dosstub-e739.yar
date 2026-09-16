rule TTP_XOR_MULT_DOSStub_e739 {
  strings:
    $key_e739 = { b3 51 [2] c7 49 [2] 80 4b [2] c7 5a [2] 89 56 [2] 85 5c [2] 92 57 [2] 89 19 [2] b4 }

  condition:
    any of them
}