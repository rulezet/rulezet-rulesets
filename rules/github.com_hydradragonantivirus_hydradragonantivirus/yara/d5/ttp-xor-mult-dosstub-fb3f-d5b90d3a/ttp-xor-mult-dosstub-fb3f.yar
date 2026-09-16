rule TTP_XOR_MULT_DOSStub_fb3f {
  strings:
    $key_fb3f = { af 57 [2] db 4f [2] 9c 4d [2] db 5c [2] 95 50 [2] 99 5a [2] 8e 51 [2] 95 1f [2] a8 }

  condition:
    any of them
}