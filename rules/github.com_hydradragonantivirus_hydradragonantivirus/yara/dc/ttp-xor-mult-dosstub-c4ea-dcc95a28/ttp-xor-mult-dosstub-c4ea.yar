rule TTP_XOR_MULT_DOSStub_c4ea {
  strings:
    $key_c4ea = { 90 82 [2] e4 9a [2] a3 98 [2] e4 89 [2] aa 85 [2] a6 8f [2] b1 84 [2] aa ca [2] 97 }

  condition:
    any of them
}