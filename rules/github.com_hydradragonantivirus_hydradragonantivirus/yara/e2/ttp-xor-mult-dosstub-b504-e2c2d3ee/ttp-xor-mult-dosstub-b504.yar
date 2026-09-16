rule TTP_XOR_MULT_DOSStub_b504 {
  strings:
    $key_b504 = { e1 6c [2] 95 74 [2] d2 76 [2] 95 67 [2] db 6b [2] d7 61 [2] c0 6a [2] db 24 [2] e6 }

  condition:
    any of them
}