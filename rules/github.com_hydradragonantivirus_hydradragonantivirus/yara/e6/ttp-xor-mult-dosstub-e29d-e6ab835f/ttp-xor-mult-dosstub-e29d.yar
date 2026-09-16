rule TTP_XOR_MULT_DOSStub_e29d {
  strings:
    $key_e29d = { b6 f5 [2] c2 ed [2] 85 ef [2] c2 fe [2] 8c f2 [2] 80 f8 [2] 97 f3 [2] 8c bd [2] b1 }

  condition:
    any of them
}