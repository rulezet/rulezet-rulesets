rule TTP_XOR_QUAD_CurrentVersionRun_131b {
  strings:
    $key_131b = { 40 74 [2] 64 7a [2] 4f 56 [2] 61 74 [2] 75 6f [2] 7a 75 [2] 64 68 [2] 66 69 [2] 7d 6f [2] 61 68 [2] 7d 47 }

  condition:
    any of them
}