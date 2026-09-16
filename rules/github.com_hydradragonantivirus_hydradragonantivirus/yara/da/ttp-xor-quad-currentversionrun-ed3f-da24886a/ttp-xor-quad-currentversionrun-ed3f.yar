rule TTP_XOR_QUAD_CurrentVersionRun_ed3f {
  strings:
    $key_ed3f = { be 50 [2] 9a 5e [2] b1 72 [2] 9f 50 [2] 8b 4b [2] 84 51 [2] 9a 4c [2] 98 4d [2] 83 4b [2] 9f 4c [2] 83 63 }

  condition:
    any of them
}