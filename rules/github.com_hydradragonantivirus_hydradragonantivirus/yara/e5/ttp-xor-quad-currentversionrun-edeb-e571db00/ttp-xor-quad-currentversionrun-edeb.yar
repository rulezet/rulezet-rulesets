rule TTP_XOR_QUAD_CurrentVersionRun_edeb {
  strings:
    $key_edeb = { be 84 [2] 9a 8a [2] b1 a6 [2] 9f 84 [2] 8b 9f [2] 84 85 [2] 9a 98 [2] 98 99 [2] 83 9f [2] 9f 98 [2] 83 b7 }

  condition:
    any of them
}