rule TTP_XOR_MULT_DOSStub_f575 {
  strings:
    $key_f575 = { a1 1d [2] d5 05 [2] 92 07 [2] d5 16 [2] 9b 1a [2] 97 10 [2] 80 1b [2] 9b 55 [2] a6 }

  condition:
    any of them
}