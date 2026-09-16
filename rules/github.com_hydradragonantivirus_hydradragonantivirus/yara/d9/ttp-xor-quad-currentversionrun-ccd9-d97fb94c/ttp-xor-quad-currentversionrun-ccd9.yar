rule TTP_XOR_QUAD_CurrentVersionRun_ccd9 {
  strings:
    $key_ccd9 = { 9f b6 [2] bb b8 [2] 90 94 [2] be b6 [2] aa ad [2] a5 b7 [2] bb aa [2] b9 ab [2] a2 ad [2] be aa [2] a2 85 }

  condition:
    any of them
}