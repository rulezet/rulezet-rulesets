rule TTP_XOR_MULT_DOSStub_fa9d {
  strings:
    $key_fa9d = { ae f5 [2] da ed [2] 9d ef [2] da fe [2] 94 f2 [2] 98 f8 [2] 8f f3 [2] 94 bd [2] a9 }

  condition:
    any of them
}