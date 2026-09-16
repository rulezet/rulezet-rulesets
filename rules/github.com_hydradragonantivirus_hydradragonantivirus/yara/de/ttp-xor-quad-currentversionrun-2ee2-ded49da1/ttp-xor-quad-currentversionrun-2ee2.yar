rule TTP_XOR_QUAD_CurrentVersionRun_2ee2 {
  strings:
    $key_2ee2 = { 7d 8d [2] 59 83 [2] 72 af [2] 5c 8d [2] 48 96 [2] 47 8c [2] 59 91 [2] 5b 90 [2] 40 96 [2] 5c 91 [2] 40 be }

  condition:
    any of them
}