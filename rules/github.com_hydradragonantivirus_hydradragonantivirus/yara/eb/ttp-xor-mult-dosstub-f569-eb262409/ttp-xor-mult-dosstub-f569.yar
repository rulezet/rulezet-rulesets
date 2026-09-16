rule TTP_XOR_MULT_DOSStub_f569 {
  strings:
    $key_f569 = { a1 01 [2] d5 19 [2] 92 1b [2] d5 0a [2] 9b 06 [2] 97 0c [2] 80 07 [2] 9b 49 [2] a6 }

  condition:
    any of them
}