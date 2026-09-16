rule TTP_XOR_QUAD_CurrentVersionRun_e91f {
  strings:
    $key_e91f = { ba 70 [2] 9e 7e [2] b5 52 [2] 9b 70 [2] 8f 6b [2] 80 71 [2] 9e 6c [2] 9c 6d [2] 87 6b [2] 9b 6c [2] 87 43 }

  condition:
    any of them
}