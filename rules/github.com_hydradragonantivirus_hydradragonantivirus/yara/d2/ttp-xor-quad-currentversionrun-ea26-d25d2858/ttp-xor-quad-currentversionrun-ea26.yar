rule TTP_XOR_QUAD_CurrentVersionRun_ea26 {
  strings:
    $key_ea26 = { b9 49 [2] 9d 47 [2] b6 6b [2] 98 49 [2] 8c 52 [2] 83 48 [2] 9d 55 [2] 9f 54 [2] 84 52 [2] 98 55 [2] 84 7a }

  condition:
    any of them
}