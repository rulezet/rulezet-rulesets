rule TTP_XOR_QUAD_CurrentVersionRun_184f {
  strings:
    $key_184f = { 4b 20 [2] 6f 2e [2] 44 02 [2] 6a 20 [2] 7e 3b [2] 71 21 [2] 6f 3c [2] 6d 3d [2] 76 3b [2] 6a 3c [2] 76 13 }

  condition:
    any of them
}