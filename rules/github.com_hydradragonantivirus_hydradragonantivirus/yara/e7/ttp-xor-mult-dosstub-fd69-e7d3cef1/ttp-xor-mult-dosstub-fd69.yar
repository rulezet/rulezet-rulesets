rule TTP_XOR_MULT_DOSStub_fd69 {
  strings:
    $key_fd69 = { a9 01 [2] dd 19 [2] 9a 1b [2] dd 0a [2] 93 06 [2] 9f 0c [2] 88 07 [2] 93 49 [2] ae }

  condition:
    any of them
}