rule TTP_XOR_MULT_DOSStub_94ed {
  strings:
    $key_94ed = { c0 85 [2] b4 9d [2] f3 9f [2] b4 8e [2] fa 82 [2] f6 88 [2] e1 83 [2] fa cd [2] c7 }

  condition:
    any of them
}