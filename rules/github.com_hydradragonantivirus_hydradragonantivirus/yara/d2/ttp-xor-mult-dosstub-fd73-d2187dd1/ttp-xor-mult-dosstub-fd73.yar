rule TTP_XOR_MULT_DOSStub_fd73 {
  strings:
    $key_fd73 = { a9 1b [2] dd 03 [2] 9a 01 [2] dd 10 [2] 93 1c [2] 9f 16 [2] 88 1d [2] 93 53 [2] ae }

  condition:
    any of them
}