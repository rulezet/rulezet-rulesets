rule TTP_XOR_MULT_DOSStub_c223 {
  strings:
    $key_c223 = { 96 4b [2] e2 53 [2] a5 51 [2] e2 40 [2] ac 4c [2] a0 46 [2] b7 4d [2] ac 03 [2] 91 }

  condition:
    any of them
}