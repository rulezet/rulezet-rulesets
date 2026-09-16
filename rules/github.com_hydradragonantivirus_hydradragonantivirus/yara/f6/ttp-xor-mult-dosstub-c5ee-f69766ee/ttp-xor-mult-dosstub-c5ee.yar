rule TTP_XOR_MULT_DOSStub_c5ee {
  strings:
    $key_c5ee = { 91 86 [2] e5 9e [2] a2 9c [2] e5 8d [2] ab 81 [2] a7 8b [2] b0 80 [2] ab ce [2] 96 }

  condition:
    any of them
}