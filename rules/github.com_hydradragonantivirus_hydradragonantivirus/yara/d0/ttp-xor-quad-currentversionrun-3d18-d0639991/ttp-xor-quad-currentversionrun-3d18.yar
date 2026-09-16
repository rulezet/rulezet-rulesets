rule TTP_XOR_QUAD_CurrentVersionRun_3d18 {
  strings:
    $key_3d18 = { 6e 77 [2] 4a 79 [2] 61 55 [2] 4f 77 [2] 5b 6c [2] 54 76 [2] 4a 6b [2] 48 6a [2] 53 6c [2] 4f 6b [2] 53 44 }

  condition:
    any of them
}