rule TTP_XOR_MULT_DOSStub_fb0f {
  strings:
    $key_fb0f = { af 67 [2] db 7f [2] 9c 7d [2] db 6c [2] 95 60 [2] 99 6a [2] 8e 61 [2] 95 2f [2] a8 }

  condition:
    any of them
}