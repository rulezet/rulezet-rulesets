rule TTP_XOR_QUAD_CurrentVersionRun_083d {
  strings:
    $key_083d = { 5b 52 [2] 7f 5c [2] 54 70 [2] 7a 52 [2] 6e 49 [2] 61 53 [2] 7f 4e [2] 7d 4f [2] 66 49 [2] 7a 4e [2] 66 61 }

  condition:
    any of them
}