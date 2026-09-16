rule TTP_XOR_QUAD_CurrentVersionRun_3d38 {
  strings:
    $key_3d38 = { 6e 57 [2] 4a 59 [2] 61 75 [2] 4f 57 [2] 5b 4c [2] 54 56 [2] 4a 4b [2] 48 4a [2] 53 4c [2] 4f 4b [2] 53 64 }

  condition:
    any of them
}