rule TTP_XOR_MULT_DOSStub_f49d {
  strings:
    $key_f49d = { a0 f5 [2] d4 ed [2] 93 ef [2] d4 fe [2] 9a f2 [2] 96 f8 [2] 81 f3 [2] 9a bd [2] a7 }

  condition:
    any of them
}