rule TTP_XOR_QUAD_CurrentVersionRun_0522 {
  strings:
    $key_0522 = { 56 4d [2] 72 43 [2] 59 6f [2] 77 4d [2] 63 56 [2] 6c 4c [2] 72 51 [2] 70 50 [2] 6b 56 [2] 77 51 [2] 6b 7e }

  condition:
    any of them
}