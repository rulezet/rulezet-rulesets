rule TTP_XOR_QUAD_CurrentVersionRun_f93d {
  strings:
    $key_f93d = { aa 52 [2] 8e 5c [2] a5 70 [2] 8b 52 [2] 9f 49 [2] 90 53 [2] 8e 4e [2] 8c 4f [2] 97 49 [2] 8b 4e [2] 97 61 }

  condition:
    any of them
}