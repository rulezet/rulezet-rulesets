rule TTP_XOR_MULT_DOSStub_fd80 {
  strings:
    $key_fd80 = { a9 e8 [2] dd f0 [2] 9a f2 [2] dd e3 [2] 93 ef [2] 9f e5 [2] 88 ee [2] 93 a0 [2] ae }

  condition:
    any of them
}