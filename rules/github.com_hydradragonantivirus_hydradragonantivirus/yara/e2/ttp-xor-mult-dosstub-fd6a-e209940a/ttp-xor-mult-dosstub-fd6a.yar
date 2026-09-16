rule TTP_XOR_MULT_DOSStub_fd6a {
  strings:
    $key_fd6a = { a9 02 [2] dd 1a [2] 9a 18 [2] dd 09 [2] 93 05 [2] 9f 0f [2] 88 04 [2] 93 4a [2] ae }

  condition:
    any of them
}