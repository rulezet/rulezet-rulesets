rule TTP_XOR_MULT_DOSStub_cb05 {
  strings:
    $key_cb05 = { 9f 6d [2] eb 75 [2] ac 77 [2] eb 66 [2] a5 6a [2] a9 60 [2] be 6b [2] a5 25 [2] 98 }

  condition:
    any of them
}