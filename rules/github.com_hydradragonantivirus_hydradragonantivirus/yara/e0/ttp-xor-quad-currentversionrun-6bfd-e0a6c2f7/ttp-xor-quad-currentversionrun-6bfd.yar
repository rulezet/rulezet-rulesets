rule TTP_XOR_QUAD_CurrentVersionRun_6bfd {
  strings:
    $key_6bfd = { 38 92 [2] 1c 9c [2] 37 b0 [2] 19 92 [2] 0d 89 [2] 02 93 [2] 1c 8e [2] 1e 8f [2] 05 89 [2] 19 8e [2] 05 a1 }

  condition:
    any of them
}