rule TTP_XOR_MULT_DOSStub_6baf {
  strings:
    $key_6baf = { 3f c7 [2] 4b df [2] 0c dd [2] 4b cc [2] 05 c0 [2] 09 ca [2] 1e c1 [2] 05 8f [2] 38 }

  condition:
    any of them
}