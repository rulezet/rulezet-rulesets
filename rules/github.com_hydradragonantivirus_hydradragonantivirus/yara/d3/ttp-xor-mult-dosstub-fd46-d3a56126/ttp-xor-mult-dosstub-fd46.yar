rule TTP_XOR_MULT_DOSStub_fd46 {
  strings:
    $key_fd46 = { a9 2e [2] dd 36 [2] 9a 34 [2] dd 25 [2] 93 29 [2] 9f 23 [2] 88 28 [2] 93 66 [2] ae }

  condition:
    any of them
}