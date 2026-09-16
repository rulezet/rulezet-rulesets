rule TTP_XOR_QUAD_CurrentVersionRun_f3d9 {
  strings:
    $key_f3d9 = { a0 b6 [2] 84 b8 [2] af 94 [2] 81 b6 [2] 95 ad [2] 9a b7 [2] 84 aa [2] 86 ab [2] 9d ad [2] 81 aa [2] 9d 85 }

  condition:
    any of them
}