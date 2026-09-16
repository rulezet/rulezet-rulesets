rule TTP_XOR_MULT_DOSStub_099d {
  strings:
    $key_099d = { 5d f5 [2] 29 ed [2] 6e ef [2] 29 fe [2] 67 f2 [2] 6b f8 [2] 7c f3 [2] 67 bd [2] 5a }

  condition:
    any of them
}