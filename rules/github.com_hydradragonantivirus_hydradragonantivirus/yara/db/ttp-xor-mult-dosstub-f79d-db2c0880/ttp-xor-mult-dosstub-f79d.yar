rule TTP_XOR_MULT_DOSStub_f79d {
  strings:
    $key_f79d = { a3 f5 [2] d7 ed [2] 90 ef [2] d7 fe [2] 99 f2 [2] 95 f8 [2] 82 f3 [2] 99 bd [2] a4 }

  condition:
    any of them
}