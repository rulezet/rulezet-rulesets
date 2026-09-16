rule TTP_XOR_QUAD_CurrentVersionRun_3f4f {
  strings:
    $key_3f4f = { 6c 20 [2] 48 2e [2] 63 02 [2] 4d 20 [2] 59 3b [2] 56 21 [2] 48 3c [2] 4a 3d [2] 51 3b [2] 4d 3c [2] 51 13 }

  condition:
    any of them
}