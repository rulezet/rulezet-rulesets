rule TTP_XOR_QUAD_CurrentVersionRun_5430 {
  strings:
    $key_5430 = { 07 5f [2] 23 51 [2] 08 7d [2] 26 5f [2] 32 44 [2] 3d 5e [2] 23 43 [2] 21 42 [2] 3a 44 [2] 26 43 [2] 3a 6c }

  condition:
    any of them
}