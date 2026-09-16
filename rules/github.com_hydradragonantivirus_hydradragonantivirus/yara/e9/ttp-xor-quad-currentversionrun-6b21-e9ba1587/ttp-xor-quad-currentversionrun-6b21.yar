rule TTP_XOR_QUAD_CurrentVersionRun_6b21 {
  strings:
    $key_6b21 = { 38 4e [2] 1c 40 [2] 37 6c [2] 19 4e [2] 0d 55 [2] 02 4f [2] 1c 52 [2] 1e 53 [2] 05 55 [2] 19 52 [2] 05 7d }

  condition:
    any of them
}