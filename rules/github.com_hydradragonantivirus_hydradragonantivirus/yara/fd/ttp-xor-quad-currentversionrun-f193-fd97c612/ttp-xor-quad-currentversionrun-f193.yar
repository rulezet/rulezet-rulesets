rule TTP_XOR_QUAD_CurrentVersionRun_f193 {
  strings:
    $key_f193 = { a2 fc [2] 86 f2 [2] ad de [2] 83 fc [2] 97 e7 [2] 98 fd [2] 86 e0 [2] 84 e1 [2] 9f e7 [2] 83 e0 [2] 9f cf }

  condition:
    any of them
}