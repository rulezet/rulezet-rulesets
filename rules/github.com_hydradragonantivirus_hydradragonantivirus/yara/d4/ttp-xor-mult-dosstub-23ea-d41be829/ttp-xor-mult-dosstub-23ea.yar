rule TTP_XOR_MULT_DOSStub_23ea {
  strings:
    $key_23ea = { 77 82 [2] 03 9a [2] 44 98 [2] 03 89 [2] 4d 85 [2] 41 8f [2] 56 84 [2] 4d ca [2] 70 }

  condition:
    any of them
}