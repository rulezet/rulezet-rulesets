rule TTP_XOR_QUAD_CurrentVersionRun_e6d9 {
  strings:
    $key_e6d9 = { b5 b6 [2] 91 b8 [2] ba 94 [2] 94 b6 [2] 80 ad [2] 8f b7 [2] 91 aa [2] 93 ab [2] 88 ad [2] 94 aa [2] 88 85 }

  condition:
    any of them
}