rule TTP_XOR_QUAD_CurrentVersionRun_33be {
  strings:
    $key_33be = { 60 d1 [2] 44 df [2] 6f f3 [2] 41 d1 [2] 55 ca [2] 5a d0 [2] 44 cd [2] 46 cc [2] 5d ca [2] 41 cd [2] 5d e2 }

  condition:
    any of them
}