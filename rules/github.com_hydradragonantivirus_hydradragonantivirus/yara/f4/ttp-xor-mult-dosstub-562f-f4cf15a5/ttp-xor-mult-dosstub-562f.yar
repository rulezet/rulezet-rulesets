rule TTP_XOR_MULT_DOSStub_562f {
  strings:
    $key_562f = { 02 47 [2] 76 5f [2] 31 5d [2] 76 4c [2] 38 40 [2] 34 4a [2] 23 41 [2] 38 0f [2] 05 }

  condition:
    any of them
}