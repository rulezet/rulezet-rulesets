rule TTP_XOR_MULT_DOSStub_343f {
  strings:
    $key_343f = { 60 57 [2] 14 4f [2] 53 4d [2] 14 5c [2] 5a 50 [2] 56 5a [2] 41 51 [2] 5a 1f [2] 67 }

  condition:
    any of them
}