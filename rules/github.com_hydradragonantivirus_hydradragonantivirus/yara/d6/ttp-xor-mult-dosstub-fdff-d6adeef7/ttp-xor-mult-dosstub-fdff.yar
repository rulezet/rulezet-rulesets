rule TTP_XOR_MULT_DOSStub_fdff {
  strings:
    $key_fdff = { a9 97 [2] dd 8f [2] 9a 8d [2] dd 9c [2] 93 90 [2] 9f 9a [2] 88 91 [2] 93 df [2] ae }

  condition:
    any of them
}