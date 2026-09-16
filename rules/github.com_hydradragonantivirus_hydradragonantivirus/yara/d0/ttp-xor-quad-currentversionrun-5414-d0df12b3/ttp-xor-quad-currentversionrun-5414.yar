rule TTP_XOR_QUAD_CurrentVersionRun_5414 {
  strings:
    $key_5414 = { 07 7b [2] 23 75 [2] 08 59 [2] 26 7b [2] 32 60 [2] 3d 7a [2] 23 67 [2] 21 66 [2] 3a 60 [2] 26 67 [2] 3a 48 }

  condition:
    any of them
}