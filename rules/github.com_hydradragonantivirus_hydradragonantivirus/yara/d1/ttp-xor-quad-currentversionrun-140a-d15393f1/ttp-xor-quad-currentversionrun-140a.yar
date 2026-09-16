rule TTP_XOR_QUAD_CurrentVersionRun_140a {
  strings:
    $key_140a = { 47 65 [2] 63 6b [2] 48 47 [2] 66 65 [2] 72 7e [2] 7d 64 [2] 63 79 [2] 61 78 [2] 7a 7e [2] 66 79 [2] 7a 56 }

  condition:
    any of them
}