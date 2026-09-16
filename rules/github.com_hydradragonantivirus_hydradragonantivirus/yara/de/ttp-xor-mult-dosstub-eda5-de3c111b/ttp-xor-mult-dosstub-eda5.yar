rule TTP_XOR_MULT_DOSStub_eda5 {
  strings:
    $key_eda5 = { b9 cd [2] cd d5 [2] 8a d7 [2] cd c6 [2] 83 ca [2] 8f c0 [2] 98 cb [2] 83 85 [2] be }

  condition:
    any of them
}