rule TTP_XOR_QUAD_CurrentVersionRun_eaeb {
  strings:
    $key_eaeb = { b9 84 [2] 9d 8a [2] b6 a6 [2] 98 84 [2] 8c 9f [2] 83 85 [2] 9d 98 [2] 9f 99 [2] 84 9f [2] 98 98 [2] 84 b7 }

  condition:
    any of them
}