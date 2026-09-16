rule TTP_XOR_MULT_DOSStub_fd24 {
  strings:
    $key_fd24 = { a9 4c [2] dd 54 [2] 9a 56 [2] dd 47 [2] 93 4b [2] 9f 41 [2] 88 4a [2] 93 04 [2] ae }

  condition:
    any of them
}