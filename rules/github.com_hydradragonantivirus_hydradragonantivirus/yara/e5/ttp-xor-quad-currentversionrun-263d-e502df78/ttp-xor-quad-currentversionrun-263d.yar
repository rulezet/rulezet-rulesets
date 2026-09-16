rule TTP_XOR_QUAD_CurrentVersionRun_263d {
  strings:
    $key_263d = { 75 52 [2] 51 5c [2] 7a 70 [2] 54 52 [2] 40 49 [2] 4f 53 [2] 51 4e [2] 53 4f [2] 48 49 [2] 54 4e [2] 48 61 }

  condition:
    any of them
}