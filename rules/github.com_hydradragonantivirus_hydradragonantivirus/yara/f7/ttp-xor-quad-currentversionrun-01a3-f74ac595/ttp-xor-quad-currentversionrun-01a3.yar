rule TTP_XOR_QUAD_CurrentVersionRun_01a3 {
  strings:
    $key_01a3 = { 52 cc [2] 76 c2 [2] 5d ee [2] 73 cc [2] 67 d7 [2] 68 cd [2] 76 d0 [2] 74 d1 [2] 6f d7 [2] 73 d0 [2] 6f ff }

  condition:
    any of them
}