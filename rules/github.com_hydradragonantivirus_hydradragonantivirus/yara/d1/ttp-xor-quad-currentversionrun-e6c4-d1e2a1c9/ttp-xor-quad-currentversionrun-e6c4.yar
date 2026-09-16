rule TTP_XOR_QUAD_CurrentVersionRun_e6c4 {
  strings:
    $key_e6c4 = { b5 ab [2] 91 a5 [2] ba 89 [2] 94 ab [2] 80 b0 [2] 8f aa [2] 91 b7 [2] 93 b6 [2] 88 b0 [2] 94 b7 [2] 88 98 }

  condition:
    any of them
}