rule TTP_XOR_QUAD_CurrentVersionRun_f93f {
  strings:
    $key_f93f = { aa 50 [2] 8e 5e [2] a5 72 [2] 8b 50 [2] 9f 4b [2] 90 51 [2] 8e 4c [2] 8c 4d [2] 97 4b [2] 8b 4c [2] 97 63 }

  condition:
    any of them
}