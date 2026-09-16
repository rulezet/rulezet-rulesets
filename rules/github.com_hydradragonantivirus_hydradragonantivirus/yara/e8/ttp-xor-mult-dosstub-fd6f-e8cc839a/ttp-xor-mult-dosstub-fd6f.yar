rule TTP_XOR_MULT_DOSStub_fd6f {
  strings:
    $key_fd6f = { a9 07 [2] dd 1f [2] 9a 1d [2] dd 0c [2] 93 00 [2] 9f 0a [2] 88 01 [2] 93 4f [2] ae }

  condition:
    any of them
}