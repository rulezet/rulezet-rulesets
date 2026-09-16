rule TTP_XOR_MULT_DOSStub_796b {
  strings:
    $key_796b = { 2d 03 [2] 59 1b [2] 1e 19 [2] 59 08 [2] 17 04 [2] 1b 0e [2] 0c 05 [2] 17 4b [2] 2a }

  condition:
    any of them
}