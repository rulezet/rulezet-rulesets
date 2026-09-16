rule TTP_XOR_MULT_DOSStub_fb21 {
  strings:
    $key_fb21 = { af 49 [2] db 51 [2] 9c 53 [2] db 42 [2] 95 4e [2] 99 44 [2] 8e 4f [2] 95 01 [2] a8 }

  condition:
    any of them
}