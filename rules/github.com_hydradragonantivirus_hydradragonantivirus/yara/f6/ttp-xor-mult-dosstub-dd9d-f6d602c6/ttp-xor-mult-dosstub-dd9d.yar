rule TTP_XOR_MULT_DOSStub_dd9d {
  strings:
    $key_dd9d = { 89 f5 [2] fd ed [2] ba ef [2] fd fe [2] b3 f2 [2] bf f8 [2] a8 f3 [2] b3 bd [2] 8e }

  condition:
    any of them
}