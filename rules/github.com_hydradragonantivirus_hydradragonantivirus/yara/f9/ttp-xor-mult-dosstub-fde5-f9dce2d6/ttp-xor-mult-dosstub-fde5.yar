rule TTP_XOR_MULT_DOSStub_fde5 {
  strings:
    $key_fde5 = { a9 8d [2] dd 95 [2] 9a 97 [2] dd 86 [2] 93 8a [2] 9f 80 [2] 88 8b [2] 93 c5 [2] ae }

  condition:
    any of them
}