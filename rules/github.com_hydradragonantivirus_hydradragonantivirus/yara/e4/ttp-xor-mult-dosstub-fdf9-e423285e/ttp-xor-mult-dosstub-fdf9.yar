rule TTP_XOR_MULT_DOSStub_fdf9 {
  strings:
    $key_fdf9 = { a9 91 [2] dd 89 [2] 9a 8b [2] dd 9a [2] 93 96 [2] 9f 9c [2] 88 97 [2] 93 d9 [2] ae }

  condition:
    any of them
}