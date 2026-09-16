rule TTP_XOR_QUAD_CurrentVersionRun_19d0 {
  strings:
    $key_19d0 = { 4a bf [2] 6e b1 [2] 45 9d [2] 6b bf [2] 7f a4 [2] 70 be [2] 6e a3 [2] 6c a2 [2] 77 a4 [2] 6b a3 [2] 77 8c }

  condition:
    any of them
}