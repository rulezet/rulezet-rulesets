rule TTP_XOR_QUAD_CurrentVersionRun_eafb {
  strings:
    $key_eafb = { b9 94 [2] 9d 9a [2] b6 b6 [2] 98 94 [2] 8c 8f [2] 83 95 [2] 9d 88 [2] 9f 89 [2] 84 8f [2] 98 88 [2] 84 a7 }

  condition:
    any of them
}