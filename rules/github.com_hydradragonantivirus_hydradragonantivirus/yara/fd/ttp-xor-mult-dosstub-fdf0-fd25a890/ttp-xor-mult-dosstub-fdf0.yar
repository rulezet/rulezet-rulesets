rule TTP_XOR_MULT_DOSStub_fdf0 {
  strings:
    $key_fdf0 = { a9 98 [2] dd 80 [2] 9a 82 [2] dd 93 [2] 93 9f [2] 9f 95 [2] 88 9e [2] 93 d0 [2] ae }

  condition:
    any of them
}