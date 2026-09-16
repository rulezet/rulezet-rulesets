rule TTP_XOR_MULT_DOSStub_fd07 {
  strings:
    $key_fd07 = { a9 6f [2] dd 77 [2] 9a 75 [2] dd 64 [2] 93 68 [2] 9f 62 [2] 88 69 [2] 93 27 [2] ae }

  condition:
    any of them
}