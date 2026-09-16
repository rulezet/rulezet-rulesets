rule TTP_XOR_QUAD_CurrentVersionRun_3d29 {
  strings:
    $key_3d29 = { 6e 46 [2] 4a 48 [2] 61 64 [2] 4f 46 [2] 5b 5d [2] 54 47 [2] 4a 5a [2] 48 5b [2] 53 5d [2] 4f 5a [2] 53 75 }

  condition:
    any of them
}