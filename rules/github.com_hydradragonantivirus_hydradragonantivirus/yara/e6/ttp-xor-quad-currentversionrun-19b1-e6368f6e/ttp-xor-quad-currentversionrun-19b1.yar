rule TTP_XOR_QUAD_CurrentVersionRun_19b1 {
  strings:
    $key_19b1 = { 4a de [2] 6e d0 [2] 45 fc [2] 6b de [2] 7f c5 [2] 70 df [2] 6e c2 [2] 6c c3 [2] 77 c5 [2] 6b c2 [2] 77 ed }

  condition:
    any of them
}