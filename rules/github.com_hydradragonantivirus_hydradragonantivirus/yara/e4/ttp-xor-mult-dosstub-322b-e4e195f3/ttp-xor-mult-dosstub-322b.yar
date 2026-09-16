rule TTP_XOR_MULT_DOSStub_322b {
  strings:
    $key_322b = { 66 43 [2] 12 5b [2] 55 59 [2] 12 48 [2] 5c 44 [2] 50 4e [2] 47 45 [2] 5c 0b [2] 61 }

  condition:
    any of them
}