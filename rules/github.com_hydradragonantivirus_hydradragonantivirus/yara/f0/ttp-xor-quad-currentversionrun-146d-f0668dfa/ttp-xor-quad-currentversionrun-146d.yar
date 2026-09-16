rule TTP_XOR_QUAD_CurrentVersionRun_146d {
  strings:
    $key_146d = { 47 02 [2] 63 0c [2] 48 20 [2] 66 02 [2] 72 19 [2] 7d 03 [2] 63 1e [2] 61 1f [2] 7a 19 [2] 66 1e [2] 7a 31 }

  condition:
    any of them
}