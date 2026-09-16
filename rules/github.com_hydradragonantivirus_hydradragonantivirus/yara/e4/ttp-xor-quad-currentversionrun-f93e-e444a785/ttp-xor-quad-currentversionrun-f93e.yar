rule TTP_XOR_QUAD_CurrentVersionRun_f93e {
  strings:
    $key_f93e = { aa 51 [2] 8e 5f [2] a5 73 [2] 8b 51 [2] 9f 4a [2] 90 50 [2] 8e 4d [2] 8c 4c [2] 97 4a [2] 8b 4d [2] 97 62 }

  condition:
    any of them
}