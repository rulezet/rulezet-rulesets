rule TTP_XOR_QUAD_CurrentVersionRun_3aeb {
  strings:
    $key_3aeb = { 69 84 [2] 4d 8a [2] 66 a6 [2] 48 84 [2] 5c 9f [2] 53 85 [2] 4d 98 [2] 4f 99 [2] 54 9f [2] 48 98 [2] 54 b7 }

  condition:
    any of them
}