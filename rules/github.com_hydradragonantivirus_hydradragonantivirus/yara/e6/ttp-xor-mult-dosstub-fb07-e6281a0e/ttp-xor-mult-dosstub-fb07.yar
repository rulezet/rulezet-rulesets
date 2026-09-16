rule TTP_XOR_MULT_DOSStub_fb07 {
  strings:
    $key_fb07 = { af 6f [2] db 77 [2] 9c 75 [2] db 64 [2] 95 68 [2] 99 62 [2] 8e 69 [2] 95 27 [2] a8 }

  condition:
    any of them
}