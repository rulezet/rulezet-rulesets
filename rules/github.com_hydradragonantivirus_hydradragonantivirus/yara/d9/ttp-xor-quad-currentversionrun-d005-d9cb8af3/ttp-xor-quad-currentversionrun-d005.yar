rule TTP_XOR_QUAD_CurrentVersionRun_d005 {
  strings:
    $key_d005 = { 83 6a [2] a7 64 [2] 8c 48 [2] a2 6a [2] b6 71 [2] b9 6b [2] a7 76 [2] a5 77 [2] be 71 [2] a2 76 [2] be 59 }

  condition:
    any of them
}