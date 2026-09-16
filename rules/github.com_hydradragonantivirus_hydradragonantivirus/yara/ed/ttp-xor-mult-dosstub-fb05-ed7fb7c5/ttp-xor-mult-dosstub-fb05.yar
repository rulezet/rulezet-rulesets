rule TTP_XOR_MULT_DOSStub_fb05 {
  strings:
    $key_fb05 = { af 6d [2] db 75 [2] 9c 77 [2] db 66 [2] 95 6a [2] 99 60 [2] 8e 6b [2] 95 25 [2] a8 }

  condition:
    any of them
}