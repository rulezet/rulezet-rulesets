rule TTP_XOR_MULT_DOSStub_f605 {
  strings:
    $key_f605 = { a2 6d [2] d6 75 [2] 91 77 [2] d6 66 [2] 98 6a [2] 94 60 [2] 83 6b [2] 98 25 [2] a5 }

  condition:
    any of them
}