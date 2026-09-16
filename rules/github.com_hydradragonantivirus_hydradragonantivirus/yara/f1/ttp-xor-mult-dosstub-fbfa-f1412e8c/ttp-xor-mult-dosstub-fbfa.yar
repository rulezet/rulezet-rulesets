rule TTP_XOR_MULT_DOSStub_fbfa {
  strings:
    $key_fbfa = { af 92 [2] db 8a [2] 9c 88 [2] db 99 [2] 95 95 [2] 99 9f [2] 8e 94 [2] 95 da [2] a8 }

  condition:
    any of them
}