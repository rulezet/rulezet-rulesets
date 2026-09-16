rule TTP_XOR_QUAD_CurrentVersionRun_e866 {
  strings:
    $key_e866 = { bb 09 [2] 9f 07 [2] b4 2b [2] 9a 09 [2] 8e 12 [2] 81 08 [2] 9f 15 [2] 9d 14 [2] 86 12 [2] 9a 15 [2] 86 3a }

  condition:
    any of them
}