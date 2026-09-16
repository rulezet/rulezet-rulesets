rule TTP_XOR_MULT_DOSStub_fb6c {
  strings:
    $key_fb6c = { af 04 [2] db 1c [2] 9c 1e [2] db 0f [2] 95 03 [2] 99 09 [2] 8e 02 [2] 95 4c [2] a8 }

  condition:
    any of them
}