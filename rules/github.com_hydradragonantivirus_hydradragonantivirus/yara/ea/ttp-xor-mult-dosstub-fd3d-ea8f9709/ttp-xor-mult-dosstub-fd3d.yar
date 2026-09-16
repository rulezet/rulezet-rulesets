rule TTP_XOR_MULT_DOSStub_fd3d {
  strings:
    $key_fd3d = { a9 55 [2] dd 4d [2] 9a 4f [2] dd 5e [2] 93 52 [2] 9f 58 [2] 88 53 [2] 93 1d [2] ae }

  condition:
    any of them
}