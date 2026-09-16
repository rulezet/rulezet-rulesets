rule TTP_XOR_MULT_DOSStub_fd02 {
  strings:
    $key_fd02 = { a9 6a [2] dd 72 [2] 9a 70 [2] dd 61 [2] 93 6d [2] 9f 67 [2] 88 6c [2] 93 22 [2] ae }

  condition:
    any of them
}