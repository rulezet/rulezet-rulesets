rule TTP_XOR_MULT_DOSStub_fb71 {
  strings:
    $key_fb71 = { af 19 [2] db 01 [2] 9c 03 [2] db 12 [2] 95 1e [2] 99 14 [2] 8e 1f [2] 95 51 [2] a8 }

  condition:
    any of them
}