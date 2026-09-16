rule TTP_XOR_MULT_DOSStub_e761 {
  strings:
    $key_e761 = { b3 09 [2] c7 11 [2] 80 13 [2] c7 02 [2] 89 0e [2] 85 04 [2] 92 0f [2] 89 41 [2] b4 }

  condition:
    any of them
}