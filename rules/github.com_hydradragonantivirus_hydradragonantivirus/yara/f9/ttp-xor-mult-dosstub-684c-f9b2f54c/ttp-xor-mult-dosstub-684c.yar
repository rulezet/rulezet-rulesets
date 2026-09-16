rule TTP_XOR_MULT_DOSStub_684c {
  strings:
    $key_684c = { 3c 24 [2] 48 3c [2] 0f 3e [2] 48 2f [2] 06 23 [2] 0a 29 [2] 1d 22 [2] 06 6c [2] 3b }

  condition:
    any of them
}