rule TTP_XOR_QUAD_CurrentVersionRun_02fb {
  strings:
    $key_02fb = { 51 94 [2] 75 9a [2] 5e b6 [2] 70 94 [2] 64 8f [2] 6b 95 [2] 75 88 [2] 77 89 [2] 6c 8f [2] 70 88 [2] 6c a7 }

  condition:
    any of them
}