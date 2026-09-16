rule TTP_XOR_QUAD_CurrentVersionRun_0021 {
  strings:
    $key_0021 = { 53 4e [2] 77 40 [2] 5c 6c [2] 72 4e [2] 66 55 [2] 69 4f [2] 77 52 [2] 75 53 [2] 6e 55 [2] 72 52 [2] 6e 7d }

  condition:
    any of them
}