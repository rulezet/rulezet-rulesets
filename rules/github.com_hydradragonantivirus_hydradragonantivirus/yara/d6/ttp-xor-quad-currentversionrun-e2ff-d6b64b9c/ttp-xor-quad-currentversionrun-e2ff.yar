rule TTP_XOR_QUAD_CurrentVersionRun_e2ff {
  strings:
    $key_e2ff = { b1 90 [2] 95 9e [2] be b2 [2] 90 90 [2] 84 8b [2] 8b 91 [2] 95 8c [2] 97 8d [2] 8c 8b [2] 90 8c [2] 8c a3 }

  condition:
    any of them
}