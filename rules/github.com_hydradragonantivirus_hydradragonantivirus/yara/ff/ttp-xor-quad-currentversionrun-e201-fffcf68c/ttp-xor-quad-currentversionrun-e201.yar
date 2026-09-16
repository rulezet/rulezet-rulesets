rule TTP_XOR_QUAD_CurrentVersionRun_e201 {
  strings:
    $key_e201 = { b1 6e [2] 95 60 [2] be 4c [2] 90 6e [2] 84 75 [2] 8b 6f [2] 95 72 [2] 97 73 [2] 8c 75 [2] 90 72 [2] 8c 5d }

  condition:
    any of them
}