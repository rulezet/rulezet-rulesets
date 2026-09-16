rule TTP_XOR_MULT_DOSStub_b9ed {
  strings:
    $key_b9ed = { ed 85 [2] 99 9d [2] de 9f [2] 99 8e [2] d7 82 [2] db 88 [2] cc 83 [2] d7 cd [2] ea }

  condition:
    any of them
}