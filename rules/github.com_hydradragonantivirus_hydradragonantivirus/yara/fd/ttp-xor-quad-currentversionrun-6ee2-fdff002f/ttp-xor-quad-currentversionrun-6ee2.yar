rule TTP_XOR_QUAD_CurrentVersionRun_6ee2 {
  strings:
    $key_6ee2 = { 3d 8d [2] 19 83 [2] 32 af [2] 1c 8d [2] 08 96 [2] 07 8c [2] 19 91 [2] 1b 90 [2] 00 96 [2] 1c 91 [2] 00 be }

  condition:
    any of them
}