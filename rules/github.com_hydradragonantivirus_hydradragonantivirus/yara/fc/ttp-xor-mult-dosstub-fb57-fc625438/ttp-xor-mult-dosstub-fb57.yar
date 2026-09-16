rule TTP_XOR_MULT_DOSStub_fb57 {
  strings:
    $key_fb57 = { af 3f [2] db 27 [2] 9c 25 [2] db 34 [2] 95 38 [2] 99 32 [2] 8e 39 [2] 95 77 [2] a8 }

  condition:
    any of them
}