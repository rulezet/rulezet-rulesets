rule TTP_XOR_MULT_DOSStub_fb76 {
  strings:
    $key_fb76 = { af 1e [2] db 06 [2] 9c 04 [2] db 15 [2] 95 19 [2] 99 13 [2] 8e 18 [2] 95 56 [2] a8 }

  condition:
    any of them
}