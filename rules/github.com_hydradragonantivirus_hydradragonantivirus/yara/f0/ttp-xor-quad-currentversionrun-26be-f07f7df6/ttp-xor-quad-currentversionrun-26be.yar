rule TTP_XOR_QUAD_CurrentVersionRun_26be {
  strings:
    $key_26be = { 75 d1 [2] 51 df [2] 7a f3 [2] 54 d1 [2] 40 ca [2] 4f d0 [2] 51 cd [2] 53 cc [2] 48 ca [2] 54 cd [2] 48 e2 }

  condition:
    any of them
}