rule TTP_XOR_QUAD_CurrentVersionRun_fe22 {
  strings:
    $key_fe22 = { ad 4d [2] 89 43 [2] a2 6f [2] 8c 4d [2] 98 56 [2] 97 4c [2] 89 51 [2] 8b 50 [2] 90 56 [2] 8c 51 [2] 90 7e }

  condition:
    any of them
}