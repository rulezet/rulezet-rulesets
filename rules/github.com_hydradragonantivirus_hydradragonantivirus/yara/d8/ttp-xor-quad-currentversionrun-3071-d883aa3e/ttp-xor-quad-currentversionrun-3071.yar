rule TTP_XOR_QUAD_CurrentVersionRun_3071 {
  strings:
    $key_3071 = { 63 1e [2] 47 10 [2] 6c 3c [2] 42 1e [2] 56 05 [2] 59 1f [2] 47 02 [2] 45 03 [2] 5e 05 [2] 42 02 [2] 5e 2d }

  condition:
    any of them
}