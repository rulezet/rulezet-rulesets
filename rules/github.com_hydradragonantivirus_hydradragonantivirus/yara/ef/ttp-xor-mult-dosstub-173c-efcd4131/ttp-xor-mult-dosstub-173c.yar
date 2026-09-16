rule TTP_XOR_MULT_DOSStub_173c {
  strings:
    $key_173c = { 43 54 [2] 37 4c [2] 70 4e [2] 37 5f [2] 79 53 [2] 75 59 [2] 62 52 [2] 79 1c [2] 44 }

  condition:
    any of them
}