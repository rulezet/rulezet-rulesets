rule TTP_XOR_MULT_DOSStub_b2ea {
  strings:
    $key_b2ea = { e6 82 [2] 92 9a [2] d5 98 [2] 92 89 [2] dc 85 [2] d0 8f [2] c7 84 [2] dc ca [2] e1 }

  condition:
    any of them
}