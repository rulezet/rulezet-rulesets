rule TTP_XOR_MULT_DOSStub_4f9d {
  strings:
    $key_4f9d = { 1b f5 [2] 6f ed [2] 28 ef [2] 6f fe [2] 21 f2 [2] 2d f8 [2] 3a f3 [2] 21 bd [2] 1c }

  condition:
    any of them
}