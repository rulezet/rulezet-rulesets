rule TTP_XOR_QUAD_CurrentVersionRun_ffb1 {
  strings:
    $key_ffb1 = { ac de [2] 88 d0 [2] a3 fc [2] 8d de [2] 99 c5 [2] 96 df [2] 88 c2 [2] 8a c3 [2] 91 c5 [2] 8d c2 [2] 91 ed }

  condition:
    any of them
}