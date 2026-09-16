rule TTP_XOR_MULT_DOSStub_139d {
  strings:
    $key_139d = { 47 f5 [2] 33 ed [2] 74 ef [2] 33 fe [2] 7d f2 [2] 71 f8 [2] 66 f3 [2] 7d bd [2] 40 }

  condition:
    any of them
}