rule TTP_XOR_MULT_DOSStub_fd19 {
  strings:
    $key_fd19 = { a9 71 [2] dd 69 [2] 9a 6b [2] dd 7a [2] 93 76 [2] 9f 7c [2] 88 77 [2] 93 39 [2] ae }

  condition:
    any of them
}