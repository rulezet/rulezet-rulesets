rule TTP_XOR_QUAD_CurrentVersionRun_7e22 {
  strings:
    $key_7e22 = { 2d 4d [2] 09 43 [2] 22 6f [2] 0c 4d [2] 18 56 [2] 17 4c [2] 09 51 [2] 0b 50 [2] 10 56 [2] 0c 51 [2] 10 7e }

  condition:
    any of them
}