rule TTP_XOR_QUAD_CurrentVersionRun_61be {
  strings:
    $key_61be = { 32 d1 [2] 16 df [2] 3d f3 [2] 13 d1 [2] 07 ca [2] 08 d0 [2] 16 cd [2] 14 cc [2] 0f ca [2] 13 cd [2] 0f e2 }

  condition:
    any of them
}