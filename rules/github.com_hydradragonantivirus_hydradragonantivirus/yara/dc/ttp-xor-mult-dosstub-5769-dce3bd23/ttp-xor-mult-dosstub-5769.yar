rule TTP_XOR_MULT_DOSStub_5769 {
  strings:
    $key_5769 = { 03 01 [2] 77 19 [2] 30 1b [2] 77 0a [2] 39 06 [2] 35 0c [2] 22 07 [2] 39 49 [2] 04 }

  condition:
    any of them
}