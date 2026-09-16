rule TTP_XOR_MULT_DOSStub_fb44 {
  strings:
    $key_fb44 = { af 2c [2] db 34 [2] 9c 36 [2] db 27 [2] 95 2b [2] 99 21 [2] 8e 2a [2] 95 64 [2] a8 }

  condition:
    any of them
}