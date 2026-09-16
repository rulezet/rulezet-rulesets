rule TTP_XOR_MULT_DOSStub_fbe0 {
  strings:
    $key_fbe0 = { af 88 [2] db 90 [2] 9c 92 [2] db 83 [2] 95 8f [2] 99 85 [2] 8e 8e [2] 95 c0 [2] a8 }

  condition:
    any of them
}