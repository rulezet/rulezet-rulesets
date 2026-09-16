rule TTP_XOR_QUAD_CurrentVersionRun_093d {
  strings:
    $key_093d = { 5a 52 [2] 7e 5c [2] 55 70 [2] 7b 52 [2] 6f 49 [2] 60 53 [2] 7e 4e [2] 7c 4f [2] 67 49 [2] 7b 4e [2] 67 61 }

  condition:
    any of them
}