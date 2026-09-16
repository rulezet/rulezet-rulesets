rule TTP_XOR_QUAD_CurrentVersionRun_ea2e {
  strings:
    $key_ea2e = { b9 41 [2] 9d 4f [2] b6 63 [2] 98 41 [2] 8c 5a [2] 83 40 [2] 9d 5d [2] 9f 5c [2] 84 5a [2] 98 5d [2] 84 72 }

  condition:
    any of them
}