rule TTP_XOR_MULT_DOSStub_57f2 {
  strings:
    $key_57f2 = { 03 9a [2] 77 82 [2] 30 80 [2] 77 91 [2] 39 9d [2] 35 97 [2] 22 9c [2] 39 d2 [2] 04 }

  condition:
    any of them
}