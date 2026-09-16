rule TTP_XOR_QUAD_CurrentVersionRun_cc05 {
  strings:
    $key_cc05 = { 9f 6a [2] bb 64 [2] 90 48 [2] be 6a [2] aa 71 [2] a5 6b [2] bb 76 [2] b9 77 [2] a2 71 [2] be 76 [2] a2 59 }

  condition:
    any of them
}