rule TTP_XOR_MULT_DOSStub_b969 {
  strings:
    $key_b969 = { ed 01 [2] 99 19 [2] de 1b [2] 99 0a [2] d7 06 [2] db 0c [2] cc 07 [2] d7 49 [2] ea }

  condition:
    any of them
}