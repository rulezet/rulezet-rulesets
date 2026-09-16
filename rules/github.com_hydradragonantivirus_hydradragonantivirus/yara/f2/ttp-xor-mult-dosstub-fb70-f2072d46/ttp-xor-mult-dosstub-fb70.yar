rule TTP_XOR_MULT_DOSStub_fb70 {
  strings:
    $key_fb70 = { af 18 [2] db 00 [2] 9c 02 [2] db 13 [2] 95 1f [2] 99 15 [2] 8e 1e [2] 95 50 [2] a8 }

  condition:
    any of them
}