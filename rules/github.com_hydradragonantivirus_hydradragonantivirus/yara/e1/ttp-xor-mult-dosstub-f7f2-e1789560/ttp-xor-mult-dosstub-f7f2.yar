rule TTP_XOR_MULT_DOSStub_f7f2 {
  strings:
    $key_f7f2 = { a3 9a [2] d7 82 [2] 90 80 [2] d7 91 [2] 99 9d [2] 95 97 [2] 82 9c [2] 99 d2 [2] a4 }

  condition:
    any of them
}