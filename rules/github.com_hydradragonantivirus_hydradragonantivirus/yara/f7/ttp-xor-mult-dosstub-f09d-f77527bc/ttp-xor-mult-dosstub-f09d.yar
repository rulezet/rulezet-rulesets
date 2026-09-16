rule TTP_XOR_MULT_DOSStub_f09d {
  strings:
    $key_f09d = { a4 f5 [2] d0 ed [2] 97 ef [2] d0 fe [2] 9e f2 [2] 92 f8 [2] 85 f3 [2] 9e bd [2] a3 }

  condition:
    any of them
}