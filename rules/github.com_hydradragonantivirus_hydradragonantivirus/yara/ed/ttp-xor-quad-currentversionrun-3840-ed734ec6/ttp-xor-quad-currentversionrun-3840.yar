rule TTP_XOR_QUAD_CurrentVersionRun_3840 {
  strings:
    $key_3840 = { 6b 2f [2] 4f 21 [2] 64 0d [2] 4a 2f [2] 5e 34 [2] 51 2e [2] 4f 33 [2] 4d 32 [2] 56 34 [2] 4a 33 [2] 56 1c }

  condition:
    any of them
}