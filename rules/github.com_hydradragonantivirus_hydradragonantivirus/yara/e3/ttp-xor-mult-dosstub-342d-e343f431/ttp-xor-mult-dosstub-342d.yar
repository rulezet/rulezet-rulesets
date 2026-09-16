rule TTP_XOR_MULT_DOSStub_342d {
  strings:
    $key_342d = { 60 45 [2] 14 5d [2] 53 5f [2] 14 4e [2] 5a 42 [2] 56 48 [2] 41 43 [2] 5a 0d [2] 67 }

  condition:
    any of them
}