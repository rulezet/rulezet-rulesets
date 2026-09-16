rule TTP_XOR_MULT_DOSStub_e5ea {
  strings:
    $key_e5ea = { b1 82 [2] c5 9a [2] 82 98 [2] c5 89 [2] 8b 85 [2] 87 8f [2] 90 84 [2] 8b ca [2] b6 }

  condition:
    any of them
}