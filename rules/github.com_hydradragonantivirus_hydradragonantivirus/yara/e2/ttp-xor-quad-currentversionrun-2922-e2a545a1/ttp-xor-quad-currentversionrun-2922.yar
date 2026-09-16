rule TTP_XOR_QUAD_CurrentVersionRun_2922 {
  strings:
    $key_2922 = { 7a 4d [2] 5e 43 [2] 75 6f [2] 5b 4d [2] 4f 56 [2] 40 4c [2] 5e 51 [2] 5c 50 [2] 47 56 [2] 5b 51 [2] 47 7e }

  condition:
    any of them
}