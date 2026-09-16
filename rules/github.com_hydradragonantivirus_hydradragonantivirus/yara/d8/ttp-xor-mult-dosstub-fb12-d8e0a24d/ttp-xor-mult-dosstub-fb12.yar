rule TTP_XOR_MULT_DOSStub_fb12 {
  strings:
    $key_fb12 = { af 7a [2] db 62 [2] 9c 60 [2] db 71 [2] 95 7d [2] 99 77 [2] 8e 7c [2] 95 32 [2] a8 }

  condition:
    any of them
}