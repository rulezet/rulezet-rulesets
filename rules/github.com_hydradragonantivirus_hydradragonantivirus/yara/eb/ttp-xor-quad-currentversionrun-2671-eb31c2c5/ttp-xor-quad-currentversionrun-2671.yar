rule TTP_XOR_QUAD_CurrentVersionRun_2671 {
  strings:
    $key_2671 = { 75 1e [2] 51 10 [2] 7a 3c [2] 54 1e [2] 40 05 [2] 4f 1f [2] 51 02 [2] 53 03 [2] 48 05 [2] 54 02 [2] 48 2d }

  condition:
    any of them
}