rule TTP_XOR_MULT_DOSStub_21ea {
  strings:
    $key_21ea = { 75 82 [2] 01 9a [2] 46 98 [2] 01 89 [2] 4f 85 [2] 43 8f [2] 54 84 [2] 4f ca [2] 72 }

  condition:
    any of them
}