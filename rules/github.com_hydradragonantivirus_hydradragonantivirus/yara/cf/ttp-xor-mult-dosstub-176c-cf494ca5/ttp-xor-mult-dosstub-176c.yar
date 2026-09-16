rule TTP_XOR_MULT_DOSStub_176c {
  strings:
    $key_176c = { 43 04 [2] 37 1c [2] 70 1e [2] 37 0f [2] 79 03 [2] 75 09 [2] 62 02 [2] 79 4c [2] 44 }

  condition:
    any of them
}