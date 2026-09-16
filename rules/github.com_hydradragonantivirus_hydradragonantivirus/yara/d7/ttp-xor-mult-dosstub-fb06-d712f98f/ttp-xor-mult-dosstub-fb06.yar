rule TTP_XOR_MULT_DOSStub_fb06 {
  strings:
    $key_fb06 = { af 6e [2] db 76 [2] 9c 74 [2] db 65 [2] 95 69 [2] 99 63 [2] 8e 68 [2] 95 26 [2] a8 }

  condition:
    any of them
}