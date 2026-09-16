rule TTP_XOR_QUAD_CurrentVersionRun_58cd {
  strings:
    $key_58cd = { 0b a2 [2] 2f ac [2] 04 80 [2] 2a a2 [2] 3e b9 [2] 31 a3 [2] 2f be [2] 2d bf [2] 36 b9 [2] 2a be [2] 36 91 }

  condition:
    any of them
}