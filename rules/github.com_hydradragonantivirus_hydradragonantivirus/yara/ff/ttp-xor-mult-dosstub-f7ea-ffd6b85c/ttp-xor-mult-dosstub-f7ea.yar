rule TTP_XOR_MULT_DOSStub_f7ea {
  strings:
    $key_f7ea = { a3 82 [2] d7 9a [2] 90 98 [2] d7 89 [2] 99 85 [2] 95 8f [2] 82 84 [2] 99 ca [2] a4 }

  condition:
    any of them
}