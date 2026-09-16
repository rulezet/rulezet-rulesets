rule TTP_XOR_QUAD_CurrentVersionRun_21c5 {
  strings:
    $key_21c5 = { 72 aa [2] 56 a4 [2] 7d 88 [2] 53 aa [2] 47 b1 [2] 48 ab [2] 56 b6 [2] 54 b7 [2] 4f b1 [2] 53 b6 [2] 4f 99 }

  condition:
    any of them
}