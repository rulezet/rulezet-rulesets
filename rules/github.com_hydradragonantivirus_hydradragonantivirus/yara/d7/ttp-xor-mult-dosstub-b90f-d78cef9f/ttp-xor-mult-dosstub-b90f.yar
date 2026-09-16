rule TTP_XOR_MULT_DOSStub_b90f {
  strings:
    $key_b90f = { ed 67 [2] 99 7f [2] de 7d [2] 99 6c [2] d7 60 [2] db 6a [2] cc 61 [2] d7 2f [2] ea }

  condition:
    any of them
}