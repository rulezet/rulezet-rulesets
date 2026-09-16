rule TTP_XOR_MULT_DOSStub_c3eb {
  strings:
    $key_c3eb = { 97 83 [2] e3 9b [2] a4 99 [2] e3 88 [2] ad 84 [2] a1 8e [2] b6 85 [2] ad cb [2] 90 }

  condition:
    any of them
}