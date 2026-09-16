rule TTP_XOR_QUAD_CurrentVersionRun_eae2 {
  strings:
    $key_eae2 = { b9 8d [2] 9d 83 [2] b6 af [2] 98 8d [2] 8c 96 [2] 83 8c [2] 9d 91 [2] 9f 90 [2] 84 96 [2] 98 91 [2] 84 be }

  condition:
    any of them
}