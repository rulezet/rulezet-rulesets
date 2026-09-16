rule TTP_XOR_QUAD_CurrentVersionRun_3e3d {
  strings:
    $key_3e3d = { 6d 52 [2] 49 5c [2] 62 70 [2] 4c 52 [2] 58 49 [2] 57 53 [2] 49 4e [2] 4b 4f [2] 50 49 [2] 4c 4e [2] 50 61 }

  condition:
    any of them
}