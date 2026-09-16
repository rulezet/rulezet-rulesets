rule TTP_XOR_QUAD_CurrentVersionRun_29cd {
  strings:
    $key_29cd = { 7a a2 [2] 5e ac [2] 75 80 [2] 5b a2 [2] 4f b9 [2] 40 a3 [2] 5e be [2] 5c bf [2] 47 b9 [2] 5b be [2] 47 91 }

  condition:
    any of them
}