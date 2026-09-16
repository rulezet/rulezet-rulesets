rule TTP_XOR_MULT_DOSStub_b523 {
  strings:
    $key_b523 = { e1 4b [2] 95 53 [2] d2 51 [2] 95 40 [2] db 4c [2] d7 46 [2] c0 4d [2] db 03 [2] e6 }

  condition:
    any of them
}