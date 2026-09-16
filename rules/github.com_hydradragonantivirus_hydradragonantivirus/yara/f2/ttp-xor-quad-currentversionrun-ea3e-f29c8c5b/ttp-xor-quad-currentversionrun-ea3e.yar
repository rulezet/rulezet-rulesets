rule TTP_XOR_QUAD_CurrentVersionRun_ea3e {
  strings:
    $key_ea3e = { b9 51 [2] 9d 5f [2] b6 73 [2] 98 51 [2] 8c 4a [2] 83 50 [2] 9d 4d [2] 9f 4c [2] 84 4a [2] 98 4d [2] 84 62 }

  condition:
    any of them
}