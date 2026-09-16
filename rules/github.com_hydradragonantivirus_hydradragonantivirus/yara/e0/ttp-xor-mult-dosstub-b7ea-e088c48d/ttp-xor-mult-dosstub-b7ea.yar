rule TTP_XOR_MULT_DOSStub_b7ea {
  strings:
    $key_b7ea = { e3 82 [2] 97 9a [2] d0 98 [2] 97 89 [2] d9 85 [2] d5 8f [2] c2 84 [2] d9 ca [2] e4 }

  condition:
    any of them
}