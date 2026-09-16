rule TTP_XOR_MULT_DOSStub_ee19 {
  strings:
    $key_ee19 = { ba 71 [2] ce 69 [2] 89 6b [2] ce 7a [2] 80 76 [2] 8c 7c [2] 9b 77 [2] 80 39 [2] bd }

  condition:
    any of them
}