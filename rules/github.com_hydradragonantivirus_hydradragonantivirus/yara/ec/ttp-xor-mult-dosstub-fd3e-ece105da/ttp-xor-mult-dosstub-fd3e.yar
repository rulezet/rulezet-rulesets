rule TTP_XOR_MULT_DOSStub_fd3e {
  strings:
    $key_fd3e = { a9 56 [2] dd 4e [2] 9a 4c [2] dd 5d [2] 93 51 [2] 9f 5b [2] 88 50 [2] 93 1e [2] ae }

  condition:
    any of them
}