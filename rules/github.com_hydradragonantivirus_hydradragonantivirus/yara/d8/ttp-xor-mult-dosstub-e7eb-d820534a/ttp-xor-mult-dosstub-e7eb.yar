rule TTP_XOR_MULT_DOSStub_e7eb {
  strings:
    $key_e7eb = { b3 83 [2] c7 9b [2] 80 99 [2] c7 88 [2] 89 84 [2] 85 8e [2] 92 85 [2] 89 cb [2] b4 }

  condition:
    any of them
}