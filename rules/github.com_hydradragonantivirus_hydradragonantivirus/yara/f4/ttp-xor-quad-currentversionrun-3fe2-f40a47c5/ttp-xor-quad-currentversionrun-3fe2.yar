rule TTP_XOR_QUAD_CurrentVersionRun_3fe2 {
  strings:
    $key_3fe2 = { 6c 8d [2] 48 83 [2] 63 af [2] 4d 8d [2] 59 96 [2] 56 8c [2] 48 91 [2] 4a 90 [2] 51 96 [2] 4d 91 [2] 51 be }

  condition:
    any of them
}