rule TTP_XOR_MULT_DOSStub_fd14 {
  strings:
    $key_fd14 = { a9 7c [2] dd 64 [2] 9a 66 [2] dd 77 [2] 93 7b [2] 9f 71 [2] 88 7a [2] 93 34 [2] ae }

  condition:
    any of them
}