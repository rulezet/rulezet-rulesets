rule TTP_XOR_MULT_DOSStub_fd34 {
  strings:
    $key_fd34 = { a9 5c [2] dd 44 [2] 9a 46 [2] dd 57 [2] 93 5b [2] 9f 51 [2] 88 5a [2] 93 14 [2] ae }

  condition:
    any of them
}