rule TTP_XOR_MULT_DOSStub_552b {
  strings:
    $key_552b = { 01 43 [2] 75 5b [2] 32 59 [2] 75 48 [2] 3b 44 [2] 37 4e [2] 20 45 [2] 3b 0b [2] 06 }

  condition:
    any of them
}