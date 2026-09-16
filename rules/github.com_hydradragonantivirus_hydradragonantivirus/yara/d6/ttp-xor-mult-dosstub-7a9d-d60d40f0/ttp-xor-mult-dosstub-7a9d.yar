rule TTP_XOR_MULT_DOSStub_7a9d {
  strings:
    $key_7a9d = { 2e f5 [2] 5a ed [2] 1d ef [2] 5a fe [2] 14 f2 [2] 18 f8 [2] 0f f3 [2] 14 bd [2] 29 }

  condition:
    any of them
}