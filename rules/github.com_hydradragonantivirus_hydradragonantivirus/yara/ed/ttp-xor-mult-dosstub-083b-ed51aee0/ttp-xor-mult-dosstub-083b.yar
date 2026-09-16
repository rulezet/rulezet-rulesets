rule TTP_XOR_MULT_DOSStub_083b {
  strings:
    $key_083b = { 5c 53 [2] 28 4b [2] 6f 49 [2] 28 58 [2] 66 54 [2] 6a 5e [2] 7d 55 [2] 66 1b [2] 5b }

  condition:
    any of them
}