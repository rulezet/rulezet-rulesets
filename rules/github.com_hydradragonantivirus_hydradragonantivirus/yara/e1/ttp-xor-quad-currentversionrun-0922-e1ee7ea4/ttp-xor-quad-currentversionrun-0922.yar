rule TTP_XOR_QUAD_CurrentVersionRun_0922 {
  strings:
    $key_0922 = { 5a 4d [2] 7e 43 [2] 55 6f [2] 7b 4d [2] 6f 56 [2] 60 4c [2] 7e 51 [2] 7c 50 [2] 67 56 [2] 7b 51 [2] 67 7e }

  condition:
    any of them
}