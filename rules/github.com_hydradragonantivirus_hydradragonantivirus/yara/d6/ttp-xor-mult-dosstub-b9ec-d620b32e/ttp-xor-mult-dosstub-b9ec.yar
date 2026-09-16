rule TTP_XOR_MULT_DOSStub_b9ec {
  strings:
    $key_b9ec = { ed 84 [2] 99 9c [2] de 9e [2] 99 8f [2] d7 83 [2] db 89 [2] cc 82 [2] d7 cc [2] ea }

  condition:
    any of them
}