rule TTP_XOR_MULT_DOSStub_6a9d {
  strings:
    $key_6a9d = { 3e f5 [2] 4a ed [2] 0d ef [2] 4a fe [2] 04 f2 [2] 08 f8 [2] 1f f3 [2] 04 bd [2] 39 }

  condition:
    any of them
}