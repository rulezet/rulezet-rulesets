rule TTP_XOR_QUAD_CurrentVersionRun_21c4 {
  strings:
    $key_21c4 = { 72 ab [2] 56 a5 [2] 7d 89 [2] 53 ab [2] 47 b0 [2] 48 aa [2] 56 b7 [2] 54 b6 [2] 4f b0 [2] 53 b7 [2] 4f 98 }

  condition:
    any of them
}