rule TTP_XOR_QUAD_CurrentVersionRun_78cd {
  strings:
    $key_78cd = { 2b a2 [2] 0f ac [2] 24 80 [2] 0a a2 [2] 1e b9 [2] 11 a3 [2] 0f be [2] 0d bf [2] 16 b9 [2] 0a be [2] 16 91 }

  condition:
    any of them
}