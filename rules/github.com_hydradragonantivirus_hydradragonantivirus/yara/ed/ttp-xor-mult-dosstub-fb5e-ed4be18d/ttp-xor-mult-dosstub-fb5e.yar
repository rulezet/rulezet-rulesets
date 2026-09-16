rule TTP_XOR_MULT_DOSStub_fb5e {
  strings:
    $key_fb5e = { af 36 [2] db 2e [2] 9c 2c [2] db 3d [2] 95 31 [2] 99 3b [2] 8e 30 [2] 95 7e [2] a8 }

  condition:
    any of them
}