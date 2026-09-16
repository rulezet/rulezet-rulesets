rule TTP_XOR_MULT_DOSStub_aca2 {
  strings:
    $key_aca2 = { f8 ca [2] 8c d2 [2] cb d0 [2] 8c c1 [2] c2 cd [2] ce c7 [2] d9 cc [2] c2 82 [2] ff }

  condition:
    any of them
}