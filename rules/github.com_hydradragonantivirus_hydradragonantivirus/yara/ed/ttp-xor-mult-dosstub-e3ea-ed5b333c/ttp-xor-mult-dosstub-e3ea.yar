rule TTP_XOR_MULT_DOSStub_e3ea {
  strings:
    $key_e3ea = { b7 82 [2] c3 9a [2] 84 98 [2] c3 89 [2] 8d 85 [2] 81 8f [2] 96 84 [2] 8d ca [2] b0 }

  condition:
    any of them
}