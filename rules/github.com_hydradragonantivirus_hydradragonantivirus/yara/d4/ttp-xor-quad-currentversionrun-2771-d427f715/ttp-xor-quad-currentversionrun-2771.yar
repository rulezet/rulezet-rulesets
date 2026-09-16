rule TTP_XOR_QUAD_CurrentVersionRun_2771 {
  strings:
    $key_2771 = { 74 1e [2] 50 10 [2] 7b 3c [2] 55 1e [2] 41 05 [2] 4e 1f [2] 50 02 [2] 52 03 [2] 49 05 [2] 55 02 [2] 49 2d }

  condition:
    any of them
}