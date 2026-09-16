rule TTP_XOR_QUAD_CurrentVersionRun_3f06 {
  strings:
    $key_3f06 = { 6c 69 [2] 48 67 [2] 63 4b [2] 4d 69 [2] 59 72 [2] 56 68 [2] 48 75 [2] 4a 74 [2] 51 72 [2] 4d 75 [2] 51 5a }

  condition:
    any of them
}