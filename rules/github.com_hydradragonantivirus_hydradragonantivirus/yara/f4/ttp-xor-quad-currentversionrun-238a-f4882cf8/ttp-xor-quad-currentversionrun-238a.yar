rule TTP_XOR_QUAD_CurrentVersionRun_238a {
  strings:
    $key_238a = { 70 e5 [2] 54 eb [2] 7f c7 [2] 51 e5 [2] 45 fe [2] 4a e4 [2] 54 f9 [2] 56 f8 [2] 4d fe [2] 51 f9 [2] 4d d6 }

  condition:
    any of them
}