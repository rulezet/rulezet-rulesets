rule TTP_XOR_MULT_DOSStub_f0ea {
  strings:
    $key_f0ea = { a4 82 [2] d0 9a [2] 97 98 [2] d0 89 [2] 9e 85 [2] 92 8f [2] 85 84 [2] 9e ca [2] a3 }

  condition:
    any of them
}