rule TTP_XOR_MULT_DOSStub_fb45 {
  strings:
    $key_fb45 = { af 2d [2] db 35 [2] 9c 37 [2] db 26 [2] 95 2a [2] 99 20 [2] 8e 2b [2] 95 65 [2] a8 }

  condition:
    any of them
}