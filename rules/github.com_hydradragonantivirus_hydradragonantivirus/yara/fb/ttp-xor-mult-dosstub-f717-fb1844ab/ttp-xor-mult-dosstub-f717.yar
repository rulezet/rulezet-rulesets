rule TTP_XOR_MULT_DOSStub_f717 {
  strings:
    $key_f717 = { a3 7f [2] d7 67 [2] 90 65 [2] d7 74 [2] 99 78 [2] 95 72 [2] 82 79 [2] 99 37 [2] a4 }

  condition:
    any of them
}