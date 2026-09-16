rule TTP_XOR_QUAD_CurrentVersionRun_ea3b {
  strings:
    $key_ea3b = { b9 54 [2] 9d 5a [2] b6 76 [2] 98 54 [2] 8c 4f [2] 83 55 [2] 9d 48 [2] 9f 49 [2] 84 4f [2] 98 48 [2] 84 67 }

  condition:
    any of them
}