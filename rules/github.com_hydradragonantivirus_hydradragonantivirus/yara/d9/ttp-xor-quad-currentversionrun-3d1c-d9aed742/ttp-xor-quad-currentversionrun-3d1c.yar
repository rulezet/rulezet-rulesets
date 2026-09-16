rule TTP_XOR_QUAD_CurrentVersionRun_3d1c {
  strings:
    $key_3d1c = { 6e 73 [2] 4a 7d [2] 61 51 [2] 4f 73 [2] 5b 68 [2] 54 72 [2] 4a 6f [2] 48 6e [2] 53 68 [2] 4f 6f [2] 53 40 }

  condition:
    any of them
}