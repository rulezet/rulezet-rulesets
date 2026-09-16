rule TTP_XOR_MULT_DOSStub_151f {
  strings:
    $key_151f = { 41 77 [2] 35 6f [2] 72 6d [2] 35 7c [2] 7b 70 [2] 77 7a [2] 60 71 [2] 7b 3f [2] 46 }

  condition:
    any of them
}