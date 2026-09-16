rule TTP_XOR_MULT_DOSStub_069d {
  strings:
    $key_069d = { 52 f5 [2] 26 ed [2] 61 ef [2] 26 fe [2] 68 f2 [2] 64 f8 [2] 73 f3 [2] 68 bd [2] 55 }

  condition:
    any of them
}