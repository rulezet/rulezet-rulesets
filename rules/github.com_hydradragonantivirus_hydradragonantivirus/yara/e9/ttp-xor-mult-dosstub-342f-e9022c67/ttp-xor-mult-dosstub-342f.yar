rule TTP_XOR_MULT_DOSStub_342f {
  strings:
    $key_342f = { 60 47 [2] 14 5f [2] 53 5d [2] 14 4c [2] 5a 40 [2] 56 4a [2] 41 41 [2] 5a 0f [2] 67 }

  condition:
    any of them
}