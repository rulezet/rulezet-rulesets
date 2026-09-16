rule TTP_XOR_MULT_DOSStub_a0ea {
  strings:
    $key_a0ea = { f4 82 [2] 80 9a [2] c7 98 [2] 80 89 [2] ce 85 [2] c2 8f [2] d5 84 [2] ce ca [2] f3 }

  condition:
    any of them
}