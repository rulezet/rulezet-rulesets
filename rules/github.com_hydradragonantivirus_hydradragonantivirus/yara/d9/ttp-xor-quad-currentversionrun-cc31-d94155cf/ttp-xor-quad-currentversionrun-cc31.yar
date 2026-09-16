rule TTP_XOR_QUAD_CurrentVersionRun_cc31 {
  strings:
    $key_cc31 = { 9f 5e [2] bb 50 [2] 90 7c [2] be 5e [2] aa 45 [2] a5 5f [2] bb 42 [2] b9 43 [2] a2 45 [2] be 42 [2] a2 6d }

  condition:
    any of them
}