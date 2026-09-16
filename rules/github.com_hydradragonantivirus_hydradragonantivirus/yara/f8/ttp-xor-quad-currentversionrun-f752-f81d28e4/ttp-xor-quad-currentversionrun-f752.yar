rule TTP_XOR_QUAD_CurrentVersionRun_f752 {
  strings:
    $key_f752 = { a4 3d [2] 80 33 [2] ab 1f [2] 85 3d [2] 91 26 [2] 9e 3c [2] 80 21 [2] 82 20 [2] 99 26 [2] 85 21 [2] 99 0e }

  condition:
    any of them
}