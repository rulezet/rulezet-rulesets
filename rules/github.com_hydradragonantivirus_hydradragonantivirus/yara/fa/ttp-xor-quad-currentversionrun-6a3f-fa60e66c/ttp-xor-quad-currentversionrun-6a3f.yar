rule TTP_XOR_QUAD_CurrentVersionRun_6a3f {
  strings:
    $key_6a3f = { 39 50 [2] 1d 5e [2] 36 72 [2] 18 50 [2] 0c 4b [2] 03 51 [2] 1d 4c [2] 1f 4d [2] 04 4b [2] 18 4c [2] 04 63 }

  condition:
    any of them
}