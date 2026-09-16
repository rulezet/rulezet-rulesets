rule TTP_XOR_QUAD_CurrentVersionRun_1922 {
  strings:
    $key_1922 = { 4a 4d [2] 6e 43 [2] 45 6f [2] 6b 4d [2] 7f 56 [2] 70 4c [2] 6e 51 [2] 6c 50 [2] 77 56 [2] 6b 51 [2] 77 7e }

  condition:
    any of them
}