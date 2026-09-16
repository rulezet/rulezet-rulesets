rule TTP_XOR_MULT_DOSStub_bba2 {
  strings:
    $key_bba2 = { ef ca [2] 9b d2 [2] dc d0 [2] 9b c1 [2] d5 cd [2] d9 c7 [2] ce cc [2] d5 82 [2] e8 }

  condition:
    any of them
}