rule TTP_XOR_MULT_DOSStub_ad03 {
  strings:
    $key_ad03 = { f9 6b [2] 8d 73 [2] ca 71 [2] 8d 60 [2] c3 6c [2] cf 66 [2] d8 6d [2] c3 23 [2] fe }

  condition:
    any of them
}