rule TTP_XOR_MULT_DOSStub_a76b {
  strings:
    $key_a76b = { f3 03 [2] 87 1b [2] c0 19 [2] 87 08 [2] c9 04 [2] c5 0e [2] d2 05 [2] c9 4b [2] f4 }

  condition:
    any of them
}