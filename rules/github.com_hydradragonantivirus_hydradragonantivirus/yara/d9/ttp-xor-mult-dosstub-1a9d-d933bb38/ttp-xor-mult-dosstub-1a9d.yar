rule TTP_XOR_MULT_DOSStub_1a9d {
  strings:
    $key_1a9d = { 4e f5 [2] 3a ed [2] 7d ef [2] 3a fe [2] 74 f2 [2] 78 f8 [2] 6f f3 [2] 74 bd [2] 49 }

  condition:
    any of them
}