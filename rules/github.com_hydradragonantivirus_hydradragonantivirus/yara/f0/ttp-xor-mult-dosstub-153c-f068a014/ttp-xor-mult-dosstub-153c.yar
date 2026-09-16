rule TTP_XOR_MULT_DOSStub_153c {
  strings:
    $key_153c = { 41 54 [2] 35 4c [2] 72 4e [2] 35 5f [2] 7b 53 [2] 77 59 [2] 60 52 [2] 7b 1c [2] 46 }

  condition:
    any of them
}