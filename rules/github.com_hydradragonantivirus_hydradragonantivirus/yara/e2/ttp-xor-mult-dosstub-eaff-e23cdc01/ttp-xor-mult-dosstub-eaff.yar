rule TTP_XOR_MULT_DOSStub_eaff {
  strings:
    $key_eaff = { be 97 [2] ca 8f [2] 8d 8d [2] ca 9c [2] 84 90 [2] 88 9a [2] 9f 91 [2] 84 df [2] b9 }

  condition:
    any of them
}