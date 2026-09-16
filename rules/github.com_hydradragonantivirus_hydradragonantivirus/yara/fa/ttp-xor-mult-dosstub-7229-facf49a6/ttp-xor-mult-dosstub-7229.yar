rule TTP_XOR_MULT_DOSStub_7229 {
  strings:
    $key_7229 = { 26 41 [2] 52 59 [2] 15 5b [2] 52 4a [2] 1c 46 [2] 10 4c [2] 07 47 [2] 1c 09 [2] 21 }

  condition:
    any of them
}