rule TTP_XOR_MULT_DOSStub_0254 {
  strings:
    $key_0254 = { 56 3c [2] 22 24 [2] 65 26 [2] 22 37 [2] 6c 3b [2] 60 31 [2] 77 3a [2] 6c 74 [2] 51 }

  condition:
    any of them
}