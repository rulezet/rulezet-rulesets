rule TTP_XOR_MULT_DOSStub_6a3b {
  strings:
    $key_6a3b = { 3e 53 [2] 4a 4b [2] 0d 49 [2] 4a 58 [2] 04 54 [2] 08 5e [2] 1f 55 [2] 04 1b [2] 39 }

  condition:
    any of them
}