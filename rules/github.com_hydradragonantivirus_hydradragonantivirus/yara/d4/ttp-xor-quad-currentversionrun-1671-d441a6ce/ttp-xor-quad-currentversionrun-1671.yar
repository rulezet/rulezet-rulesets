rule TTP_XOR_QUAD_CurrentVersionRun_1671 {
  strings:
    $key_1671 = { 45 1e [2] 61 10 [2] 4a 3c [2] 64 1e [2] 70 05 [2] 7f 1f [2] 61 02 [2] 63 03 [2] 78 05 [2] 64 02 [2] 78 2d }

  condition:
    any of them
}