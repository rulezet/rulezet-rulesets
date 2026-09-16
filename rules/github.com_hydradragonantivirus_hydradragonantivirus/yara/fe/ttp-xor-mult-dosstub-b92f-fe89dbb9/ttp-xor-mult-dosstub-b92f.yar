rule TTP_XOR_MULT_DOSStub_b92f {
  strings:
    $key_b92f = { ed 47 [2] 99 5f [2] de 5d [2] 99 4c [2] d7 40 [2] db 4a [2] cc 41 [2] d7 0f [2] ea }

  condition:
    any of them
}