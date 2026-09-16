rule TTP_XOR_QUAD_CurrentVersionRun_f8b1 {
  strings:
    $key_f8b1 = { ab de [2] 8f d0 [2] a4 fc [2] 8a de [2] 9e c5 [2] 91 df [2] 8f c2 [2] 8d c3 [2] 96 c5 [2] 8a c2 [2] 96 ed }

  condition:
    any of them
}