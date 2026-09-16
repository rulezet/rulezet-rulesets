rule TTP_XOR_MULT_DOSStub_fbeb {
  strings:
    $key_fbeb = { af 83 [2] db 9b [2] 9c 99 [2] db 88 [2] 95 84 [2] 99 8e [2] 8e 85 [2] 95 cb [2] a8 }

  condition:
    any of them
}