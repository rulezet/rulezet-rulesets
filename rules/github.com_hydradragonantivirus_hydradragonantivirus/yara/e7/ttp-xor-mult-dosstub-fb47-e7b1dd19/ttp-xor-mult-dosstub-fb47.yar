rule TTP_XOR_MULT_DOSStub_fb47 {
  strings:
    $key_fb47 = { af 2f [2] db 37 [2] 9c 35 [2] db 24 [2] 95 28 [2] 99 22 [2] 8e 29 [2] 95 67 [2] a8 }

  condition:
    any of them
}