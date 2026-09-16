rule TTP_XOR_MULT_DOSStub_eaed {
  strings:
    $key_eaed = { be 85 [2] ca 9d [2] 8d 9f [2] ca 8e [2] 84 82 [2] 88 88 [2] 9f 83 [2] 84 cd [2] b9 }

  condition:
    any of them
}