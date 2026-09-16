rule TTP_XOR_QUAD_CurrentVersionRun_f771 {
  strings:
    $key_f771 = { a4 1e [2] 80 10 [2] ab 3c [2] 85 1e [2] 91 05 [2] 9e 1f [2] 80 02 [2] 82 03 [2] 99 05 [2] 85 02 [2] 99 2d }

  condition:
    any of them
}