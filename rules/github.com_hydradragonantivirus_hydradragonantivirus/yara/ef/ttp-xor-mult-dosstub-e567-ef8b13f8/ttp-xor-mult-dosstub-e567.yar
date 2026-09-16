rule TTP_XOR_MULT_DOSStub_e567 {
  strings:
    $key_e567 = { b1 0f [2] c5 17 [2] 82 15 [2] c5 04 [2] 8b 08 [2] 87 02 [2] 90 09 [2] 8b 47 [2] b6 }

  condition:
    any of them
}