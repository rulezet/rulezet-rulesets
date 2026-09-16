rule TTP_XOR_MULT_DOSStub_f617 {
  strings:
    $key_f617 = { a2 7f [2] d6 67 [2] 91 65 [2] d6 74 [2] 98 78 [2] 94 72 [2] 83 79 [2] 98 37 [2] a5 }

  condition:
    any of them
}