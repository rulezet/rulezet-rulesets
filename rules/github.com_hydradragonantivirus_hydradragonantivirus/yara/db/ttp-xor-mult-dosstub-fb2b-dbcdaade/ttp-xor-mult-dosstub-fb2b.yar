rule TTP_XOR_MULT_DOSStub_fb2b {
  strings:
    $key_fb2b = { af 43 [2] db 5b [2] 9c 59 [2] db 48 [2] 95 44 [2] 99 4e [2] 8e 45 [2] 95 0b [2] a8 }

  condition:
    any of them
}