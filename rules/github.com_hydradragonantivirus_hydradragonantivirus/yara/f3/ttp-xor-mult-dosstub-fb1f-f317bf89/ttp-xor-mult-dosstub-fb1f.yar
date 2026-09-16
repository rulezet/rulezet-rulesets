rule TTP_XOR_MULT_DOSStub_fb1f {
  strings:
    $key_fb1f = { af 77 [2] db 6f [2] 9c 6d [2] db 7c [2] 95 70 [2] 99 7a [2] 8e 71 [2] 95 3f [2] a8 }

  condition:
    any of them
}