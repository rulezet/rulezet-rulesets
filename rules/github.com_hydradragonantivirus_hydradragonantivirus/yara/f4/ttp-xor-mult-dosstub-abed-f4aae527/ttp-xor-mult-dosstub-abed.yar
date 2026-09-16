rule TTP_XOR_MULT_DOSStub_abed {
  strings:
    $key_abed = { ff 85 [2] 8b 9d [2] cc 9f [2] 8b 8e [2] c5 82 [2] c9 88 [2] de 83 [2] c5 cd [2] f8 }

  condition:
    any of them
}