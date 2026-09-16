rule TTP_XOR_MULT_DOSStub_c17b {
  strings:
    $key_c17b = { 95 13 [2] e1 0b [2] a6 09 [2] e1 18 [2] af 14 [2] a3 1e [2] b4 15 [2] af 5b [2] 92 }

  condition:
    any of them
}