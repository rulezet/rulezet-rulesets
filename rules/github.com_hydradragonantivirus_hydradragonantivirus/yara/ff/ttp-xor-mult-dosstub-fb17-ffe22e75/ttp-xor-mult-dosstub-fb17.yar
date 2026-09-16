rule TTP_XOR_MULT_DOSStub_fb17 {
  strings:
    $key_fb17 = { af 7f [2] db 67 [2] 9c 65 [2] db 74 [2] 95 78 [2] 99 72 [2] 8e 79 [2] 95 37 [2] a8 }

  condition:
    any of them
}