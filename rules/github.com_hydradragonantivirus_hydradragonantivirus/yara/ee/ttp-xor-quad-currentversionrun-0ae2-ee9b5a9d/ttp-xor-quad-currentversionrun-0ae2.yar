rule TTP_XOR_QUAD_CurrentVersionRun_0ae2 {
  strings:
    $key_0ae2 = { 59 8d [2] 7d 83 [2] 56 af [2] 78 8d [2] 6c 96 [2] 63 8c [2] 7d 91 [2] 7f 90 [2] 64 96 [2] 78 91 [2] 64 be }

  condition:
    any of them
}