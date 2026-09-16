rule TTP_XOR_QUAD_CurrentVersionRun_05ce {
  strings:
    $key_05ce = { 56 a1 [2] 72 af [2] 59 83 [2] 77 a1 [2] 63 ba [2] 6c a0 [2] 72 bd [2] 70 bc [2] 6b ba [2] 77 bd [2] 6b 92 }

  condition:
    any of them
}