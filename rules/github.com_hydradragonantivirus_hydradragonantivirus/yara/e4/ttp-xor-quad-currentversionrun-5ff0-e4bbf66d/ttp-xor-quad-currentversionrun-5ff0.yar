rule TTP_XOR_QUAD_CurrentVersionRun_5ff0 {
  strings:
    $key_5ff0 = { 0c 9f [2] 28 91 [2] 03 bd [2] 2d 9f [2] 39 84 [2] 36 9e [2] 28 83 [2] 2a 82 [2] 31 84 [2] 2d 83 [2] 31 ac }

  condition:
    any of them
}