rule TTP_XOR_MULT_DOSStub_c37b {
  strings:
    $key_c37b = { 97 13 [2] e3 0b [2] a4 09 [2] e3 18 [2] ad 14 [2] a1 1e [2] b6 15 [2] ad 5b [2] 90 }

  condition:
    any of them
}