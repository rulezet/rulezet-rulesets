rule TTP_XOR_MULT_DOSStub_fb4c {
  strings:
    $key_fb4c = { af 24 [2] db 3c [2] 9c 3e [2] db 2f [2] 95 23 [2] 99 29 [2] 8e 22 [2] 95 6c [2] a8 }

  condition:
    any of them
}