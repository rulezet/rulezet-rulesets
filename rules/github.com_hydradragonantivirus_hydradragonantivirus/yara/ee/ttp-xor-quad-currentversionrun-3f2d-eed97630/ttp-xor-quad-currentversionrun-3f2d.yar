rule TTP_XOR_QUAD_CurrentVersionRun_3f2d {
  strings:
    $key_3f2d = { 6c 42 [2] 48 4c [2] 63 60 [2] 4d 42 [2] 59 59 [2] 56 43 [2] 48 5e [2] 4a 5f [2] 51 59 [2] 4d 5e [2] 51 71 }

  condition:
    any of them
}