rule TTP_XOR_MULT_DOSStub_e5e5 {
  strings:
    $key_e5e5 = { b1 8d [2] c5 95 [2] 82 97 [2] c5 86 [2] 8b 8a [2] 87 80 [2] 90 8b [2] 8b c5 [2] b6 }

  condition:
    any of them
}