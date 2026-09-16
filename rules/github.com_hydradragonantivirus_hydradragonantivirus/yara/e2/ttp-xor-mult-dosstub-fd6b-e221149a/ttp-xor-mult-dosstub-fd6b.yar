rule TTP_XOR_MULT_DOSStub_fd6b {
  strings:
    $key_fd6b = { a9 03 [2] dd 1b [2] 9a 19 [2] dd 08 [2] 93 04 [2] 9f 0e [2] 88 05 [2] 93 4b [2] ae }

  condition:
    any of them
}