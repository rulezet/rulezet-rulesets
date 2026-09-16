rule TTP_XOR_QUAD_CurrentVersionRun_3d24 {
  strings:
    $key_3d24 = { 6e 4b [2] 4a 45 [2] 61 69 [2] 4f 4b [2] 5b 50 [2] 54 4a [2] 4a 57 [2] 48 56 [2] 53 50 [2] 4f 57 [2] 53 78 }

  condition:
    any of them
}