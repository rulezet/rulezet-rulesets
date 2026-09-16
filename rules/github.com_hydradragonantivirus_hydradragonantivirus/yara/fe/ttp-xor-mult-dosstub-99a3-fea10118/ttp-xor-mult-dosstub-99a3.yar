rule TTP_XOR_MULT_DOSStub_99a3 {
  strings:
    $key_99a3 = { cd cb [2] b9 d3 [2] fe d1 [2] b9 c0 [2] f7 cc [2] fb c6 [2] ec cd [2] f7 83 [2] ca }

  condition:
    any of them
}