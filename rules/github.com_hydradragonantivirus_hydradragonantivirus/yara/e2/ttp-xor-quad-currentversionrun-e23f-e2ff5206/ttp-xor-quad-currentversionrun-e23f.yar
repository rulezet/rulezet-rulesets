rule TTP_XOR_QUAD_CurrentVersionRun_e23f {
  strings:
    $key_e23f = { b1 50 [2] 95 5e [2] be 72 [2] 90 50 [2] 84 4b [2] 8b 51 [2] 95 4c [2] 97 4d [2] 8c 4b [2] 90 4c [2] 8c 63 }

  condition:
    any of them
}