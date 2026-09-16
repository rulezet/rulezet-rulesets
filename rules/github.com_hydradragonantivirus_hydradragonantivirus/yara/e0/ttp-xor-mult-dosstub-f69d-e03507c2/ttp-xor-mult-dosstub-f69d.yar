rule TTP_XOR_MULT_DOSStub_f69d {
  strings:
    $key_f69d = { a2 f5 [2] d6 ed [2] 91 ef [2] d6 fe [2] 98 f2 [2] 94 f8 [2] 83 f3 [2] 98 bd [2] a5 }

  condition:
    any of them
}