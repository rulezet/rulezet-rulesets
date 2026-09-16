rule TTP_XOR_QUAD_CurrentVersionRun_0721 {
  strings:
    $key_0721 = { 54 4e [2] 70 40 [2] 5b 6c [2] 75 4e [2] 61 55 [2] 6e 4f [2] 70 52 [2] 72 53 [2] 69 55 [2] 75 52 [2] 69 7d }

  condition:
    any of them
}