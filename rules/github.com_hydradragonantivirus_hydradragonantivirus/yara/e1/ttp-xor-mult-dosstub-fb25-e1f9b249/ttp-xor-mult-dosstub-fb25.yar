rule TTP_XOR_MULT_DOSStub_fb25 {
  strings:
    $key_fb25 = { af 4d [2] db 55 [2] 9c 57 [2] db 46 [2] 95 4a [2] 99 40 [2] 8e 4b [2] 95 05 [2] a8 }

  condition:
    any of them
}