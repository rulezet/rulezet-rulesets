rule TTP_XOR_MULT_DOSStub_fd11 {
  strings:
    $key_fd11 = { a9 79 [2] dd 61 [2] 9a 63 [2] dd 72 [2] 93 7e [2] 9f 74 [2] 88 7f [2] 93 31 [2] ae }

  condition:
    any of them
}