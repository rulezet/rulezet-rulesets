rule TTP_XOR_QUAD_CurrentVersionRun_0aff {
  strings:
    $key_0aff = { 59 90 [2] 7d 9e [2] 56 b2 [2] 78 90 [2] 6c 8b [2] 63 91 [2] 7d 8c [2] 7f 8d [2] 64 8b [2] 78 8c [2] 64 a3 }

  condition:
    any of them
}