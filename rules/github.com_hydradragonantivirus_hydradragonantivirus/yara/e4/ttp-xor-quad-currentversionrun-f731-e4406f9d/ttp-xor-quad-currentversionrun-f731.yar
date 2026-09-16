rule TTP_XOR_QUAD_CurrentVersionRun_f731 {
  strings:
    $key_f731 = { a4 5e [2] 80 50 [2] ab 7c [2] 85 5e [2] 91 45 [2] 9e 5f [2] 80 42 [2] 82 43 [2] 99 45 [2] 85 42 [2] 99 6d }

  condition:
    any of them
}