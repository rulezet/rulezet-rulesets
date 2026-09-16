rule TTP_XOR_QUAD_CurrentVersionRun_3d05 {
  strings:
    $key_3d05 = { 6e 6a [2] 4a 64 [2] 61 48 [2] 4f 6a [2] 5b 71 [2] 54 6b [2] 4a 76 [2] 48 77 [2] 53 71 [2] 4f 76 [2] 53 59 }

  condition:
    any of them
}