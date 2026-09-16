rule TTP_XOR_MULT_DOSStub_736b {
  strings:
    $key_736b = { 27 03 [2] 53 1b [2] 14 19 [2] 53 08 [2] 1d 04 [2] 11 0e [2] 06 05 [2] 1d 4b [2] 20 }

  condition:
    any of them
}