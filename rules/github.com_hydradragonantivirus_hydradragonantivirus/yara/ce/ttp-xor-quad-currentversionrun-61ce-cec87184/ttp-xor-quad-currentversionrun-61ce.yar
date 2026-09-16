rule TTP_XOR_QUAD_CurrentVersionRun_61ce {
  strings:
    $key_61ce = { 32 a1 [2] 16 af [2] 3d 83 [2] 13 a1 [2] 07 ba [2] 08 a0 [2] 16 bd [2] 14 bc [2] 0f ba [2] 13 bd [2] 0f 92 }

  condition:
    any of them
}