rule TTP_XOR_QUAD_CurrentVersionRun_f693 {
  strings:
    $key_f693 = { a5 fc [2] 81 f2 [2] aa de [2] 84 fc [2] 90 e7 [2] 9f fd [2] 81 e0 [2] 83 e1 [2] 98 e7 [2] 84 e0 [2] 98 cf }

  condition:
    any of them
}