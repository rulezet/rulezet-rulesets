rule TTP_XOR_MULT_DOSStub_6335 {
  strings:
    $key_6335 = { 37 5d [2] 43 45 [2] 04 47 [2] 43 56 [2] 0d 5a [2] 01 50 [2] 16 5b [2] 0d 15 [2] 30 }

  condition:
    any of them
}