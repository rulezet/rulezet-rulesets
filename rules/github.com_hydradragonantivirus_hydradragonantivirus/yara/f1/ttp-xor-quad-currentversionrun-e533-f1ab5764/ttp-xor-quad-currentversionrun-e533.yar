rule TTP_XOR_QUAD_CurrentVersionRun_e533 {
  strings:
    $key_e533 = { b6 5c [2] 92 52 [2] b9 7e [2] 97 5c [2] 83 47 [2] 8c 5d [2] 92 40 [2] 90 41 [2] 8b 47 [2] 97 40 [2] 8b 6f }

  condition:
    any of them
}