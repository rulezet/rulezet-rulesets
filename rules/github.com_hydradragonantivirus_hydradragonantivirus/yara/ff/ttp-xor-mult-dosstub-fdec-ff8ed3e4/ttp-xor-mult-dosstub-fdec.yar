rule TTP_XOR_MULT_DOSStub_fdec {
  strings:
    $key_fdec = { a9 84 [2] dd 9c [2] 9a 9e [2] dd 8f [2] 93 83 [2] 9f 89 [2] 88 82 [2] 93 cc [2] ae }

  condition:
    any of them
}