rule TTP_XOR_MULT_DOSStub_b961 {
  strings:
    $key_b961 = { ed 09 [2] 99 11 [2] de 13 [2] 99 02 [2] d7 0e [2] db 04 [2] cc 0f [2] d7 41 [2] ea }

  condition:
    any of them
}