rule TTP_XOR_MULT_DOSStub_fb54 {
  strings:
    $key_fb54 = { af 3c [2] db 24 [2] 9c 26 [2] db 37 [2] 95 3b [2] 99 31 [2] 8e 3a [2] 95 74 [2] a8 }

  condition:
    any of them
}