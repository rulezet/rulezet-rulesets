rule TTP_XOR_MULT_DOSStub_e767 {
  strings:
    $key_e767 = { b3 0f [2] c7 17 [2] 80 15 [2] c7 04 [2] 89 08 [2] 85 02 [2] 92 09 [2] 89 47 [2] b4 }

  condition:
    any of them
}