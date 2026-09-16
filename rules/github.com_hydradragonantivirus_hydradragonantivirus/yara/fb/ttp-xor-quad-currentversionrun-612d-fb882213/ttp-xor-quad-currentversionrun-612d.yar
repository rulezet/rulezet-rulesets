rule TTP_XOR_QUAD_CurrentVersionRun_612d {
  strings:
    $key_612d = { 32 42 [2] 16 4c [2] 3d 60 [2] 13 42 [2] 07 59 [2] 08 43 [2] 16 5e [2] 14 5f [2] 0f 59 [2] 13 5e [2] 0f 71 }

  condition:
    any of them
}