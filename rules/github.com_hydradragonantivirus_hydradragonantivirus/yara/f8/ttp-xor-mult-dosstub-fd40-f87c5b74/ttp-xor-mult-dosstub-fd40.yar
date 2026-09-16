rule TTP_XOR_MULT_DOSStub_fd40 {
  strings:
    $key_fd40 = { a9 28 [2] dd 30 [2] 9a 32 [2] dd 23 [2] 93 2f [2] 9f 25 [2] 88 2e [2] 93 60 [2] ae }

  condition:
    any of them
}