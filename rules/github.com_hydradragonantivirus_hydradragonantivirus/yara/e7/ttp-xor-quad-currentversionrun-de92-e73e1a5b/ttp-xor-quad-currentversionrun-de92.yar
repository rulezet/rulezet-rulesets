rule TTP_XOR_QUAD_CurrentVersionRun_de92 {
  strings:
    $key_de92 = { 8d fd [2] a9 f3 [2] 82 df [2] ac fd [2] b8 e6 [2] b7 fc [2] a9 e1 [2] ab e0 [2] b0 e6 [2] ac e1 [2] b0 ce }

  condition:
    any of them
}