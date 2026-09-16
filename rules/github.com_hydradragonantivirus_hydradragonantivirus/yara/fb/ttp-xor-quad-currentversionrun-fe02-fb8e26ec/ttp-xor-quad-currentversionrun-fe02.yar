rule TTP_XOR_QUAD_CurrentVersionRun_fe02 {
  strings:
    $key_fe02 = { ad 6d [2] 89 63 [2] a2 4f [2] 8c 6d [2] 98 76 [2] 97 6c [2] 89 71 [2] 8b 70 [2] 90 76 [2] 8c 71 [2] 90 5e }

  condition:
    any of them
}