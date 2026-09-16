rule TTP_XOR_MULT_DOSStub_248b {
  strings:
    $key_248b = { 70 e3 [2] 04 fb [2] 43 f9 [2] 04 e8 [2] 4a e4 [2] 46 ee [2] 51 e5 [2] 4a ab [2] 77 }

  condition:
    any of them
}