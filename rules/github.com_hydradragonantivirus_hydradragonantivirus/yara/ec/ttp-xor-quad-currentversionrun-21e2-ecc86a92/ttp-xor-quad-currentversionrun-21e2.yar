rule TTP_XOR_QUAD_CurrentVersionRun_21e2 {
  strings:
    $key_21e2 = { 72 8d [2] 56 83 [2] 7d af [2] 53 8d [2] 47 96 [2] 48 8c [2] 56 91 [2] 54 90 [2] 4f 96 [2] 53 91 [2] 4f be }

  condition:
    any of them
}