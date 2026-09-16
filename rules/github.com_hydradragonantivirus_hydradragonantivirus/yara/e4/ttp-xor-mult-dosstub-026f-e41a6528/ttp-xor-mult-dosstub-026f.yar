rule TTP_XOR_MULT_DOSStub_026f {
  strings:
    $key_026f = { 56 07 [2] 22 1f [2] 65 1d [2] 22 0c [2] 6c 00 [2] 60 0a [2] 77 01 [2] 6c 4f [2] 51 }

  condition:
    any of them
}