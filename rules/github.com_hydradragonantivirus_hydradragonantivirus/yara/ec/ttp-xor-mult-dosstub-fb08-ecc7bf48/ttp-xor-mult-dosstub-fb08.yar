rule TTP_XOR_MULT_DOSStub_fb08 {
  strings:
    $key_fb08 = { af 60 [2] db 78 [2] 9c 7a [2] db 6b [2] 95 67 [2] 99 6d [2] 8e 66 [2] 95 28 [2] a8 }

  condition:
    any of them
}