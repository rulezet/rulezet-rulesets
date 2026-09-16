rule TTP_XOR_QUAD_CurrentVersionRun_ed7e {
  strings:
    $key_ed7e = { be 11 [2] 9a 1f [2] b1 33 [2] 9f 11 [2] 8b 0a [2] 84 10 [2] 9a 0d [2] 98 0c [2] 83 0a [2] 9f 0d [2] 83 22 }

  condition:
    any of them
}