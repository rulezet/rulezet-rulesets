rule TTP_XOR_QUAD_CurrentVersionRun_12e2 {
  strings:
    $key_12e2 = { 41 8d [2] 65 83 [2] 4e af [2] 60 8d [2] 74 96 [2] 7b 8c [2] 65 91 [2] 67 90 [2] 7c 96 [2] 60 91 [2] 7c be }

  condition:
    any of them
}