rule TTP_XOR_MULT_DOSStub_e79d {
  strings:
    $key_e79d = { b3 f5 [2] c7 ed [2] 80 ef [2] c7 fe [2] 89 f2 [2] 85 f8 [2] 92 f3 [2] 89 bd [2] b4 }

  condition:
    any of them
}