rule TTP_XOR_MULT_DOSStub_fb1b {
  strings:
    $key_fb1b = { af 73 [2] db 6b [2] 9c 69 [2] db 78 [2] 95 74 [2] 99 7e [2] 8e 75 [2] 95 3b [2] a8 }

  condition:
    any of them
}