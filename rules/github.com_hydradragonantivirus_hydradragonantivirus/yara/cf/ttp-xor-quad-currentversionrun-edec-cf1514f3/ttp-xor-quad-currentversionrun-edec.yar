rule TTP_XOR_QUAD_CurrentVersionRun_edec {
  strings:
    $key_edec = { be 83 [2] 9a 8d [2] b1 a1 [2] 9f 83 [2] 8b 98 [2] 84 82 [2] 9a 9f [2] 98 9e [2] 83 98 [2] 9f 9f [2] 83 b0 }

  condition:
    any of them
}