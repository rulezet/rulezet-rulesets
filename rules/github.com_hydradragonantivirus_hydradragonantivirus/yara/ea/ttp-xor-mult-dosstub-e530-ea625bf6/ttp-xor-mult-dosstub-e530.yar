rule TTP_XOR_MULT_DOSStub_e530 {
  strings:
    $key_e530 = { b1 58 [2] c5 40 [2] 82 42 [2] c5 53 [2] 8b 5f [2] 87 55 [2] 90 5e [2] 8b 10 [2] b6 }

  condition:
    any of them
}