rule TTP_XOR_QUAD_CurrentVersionRun_fccb {
  strings:
    $key_fccb = { af a4 [2] 8b aa [2] a0 86 [2] 8e a4 [2] 9a bf [2] 95 a5 [2] 8b b8 [2] 89 b9 [2] 92 bf [2] 8e b8 [2] 92 97 }

  condition:
    any of them
}