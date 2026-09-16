rule TTP_XOR_MULT_DOSStub_fd33 {
  strings:
    $key_fd33 = { a9 5b [2] dd 43 [2] 9a 41 [2] dd 50 [2] 93 5c [2] 9f 56 [2] 88 5d [2] 93 13 [2] ae }

  condition:
    any of them
}