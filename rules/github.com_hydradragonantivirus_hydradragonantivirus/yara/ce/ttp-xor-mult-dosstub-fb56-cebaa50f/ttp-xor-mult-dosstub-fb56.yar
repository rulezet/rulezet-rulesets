rule TTP_XOR_MULT_DOSStub_fb56 {
  strings:
    $key_fb56 = { af 3e [2] db 26 [2] 9c 24 [2] db 35 [2] 95 39 [2] 99 33 [2] 8e 38 [2] 95 76 [2] a8 }

  condition:
    any of them
}