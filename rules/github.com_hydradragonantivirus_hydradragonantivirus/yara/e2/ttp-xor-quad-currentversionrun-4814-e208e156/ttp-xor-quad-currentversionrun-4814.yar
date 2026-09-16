rule TTP_XOR_QUAD_CurrentVersionRun_4814 {
  strings:
    $key_4814 = { 1b 7b [2] 3f 75 [2] 14 59 [2] 3a 7b [2] 2e 60 [2] 21 7a [2] 3f 67 [2] 3d 66 [2] 26 60 [2] 3a 67 [2] 26 48 }

  condition:
    any of them
}