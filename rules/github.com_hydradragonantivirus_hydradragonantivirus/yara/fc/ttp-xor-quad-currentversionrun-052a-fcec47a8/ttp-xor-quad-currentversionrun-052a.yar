rule TTP_XOR_QUAD_CurrentVersionRun_052a {
  strings:
    $key_052a = { 56 45 [2] 72 4b [2] 59 67 [2] 77 45 [2] 63 5e [2] 6c 44 [2] 72 59 [2] 70 58 [2] 6b 5e [2] 77 59 [2] 6b 76 }

  condition:
    any of them
}