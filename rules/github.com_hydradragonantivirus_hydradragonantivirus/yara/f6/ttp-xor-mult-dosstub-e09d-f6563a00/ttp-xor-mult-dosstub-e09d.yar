rule TTP_XOR_MULT_DOSStub_e09d {
  strings:
    $key_e09d = { b4 f5 [2] c0 ed [2] 87 ef [2] c0 fe [2] 8e f2 [2] 82 f8 [2] 95 f3 [2] 8e bd [2] b3 }

  condition:
    any of them
}