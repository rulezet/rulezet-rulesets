rule TTP_XOR_MULT_DOSStub_f637 {
  strings:
    $key_f637 = { a2 5f [2] d6 47 [2] 91 45 [2] d6 54 [2] 98 58 [2] 94 52 [2] 83 59 [2] 98 17 [2] a5 }

  condition:
    any of them
}