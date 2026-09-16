rule TTP_XOR_MULT_DOSStub_fb7c {
  strings:
    $key_fb7c = { af 14 [2] db 0c [2] 9c 0e [2] db 1f [2] 95 13 [2] 99 19 [2] 8e 12 [2] 95 5c [2] a8 }

  condition:
    any of them
}