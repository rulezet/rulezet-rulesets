rule TTP_XOR_MULT_DOSStub_026d {
  strings:
    $key_026d = { 56 05 [2] 22 1d [2] 65 1f [2] 22 0e [2] 6c 02 [2] 60 08 [2] 77 03 [2] 6c 4d [2] 51 }

  condition:
    any of them
}