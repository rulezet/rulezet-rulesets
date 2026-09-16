rule TTP_XOR_MULT_DOSStub_f025 {
  strings:
    $key_f025 = { a4 4d [2] d0 55 [2] 97 57 [2] d0 46 [2] 9e 4a [2] 92 40 [2] 85 4b [2] 9e 05 [2] a3 }

  condition:
    any of them
}