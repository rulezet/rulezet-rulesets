rule TTP_XOR_QUAD_CurrentVersionRun_30ff {
  strings:
    $key_30ff = { 63 90 [2] 47 9e [2] 6c b2 [2] 42 90 [2] 56 8b [2] 59 91 [2] 47 8c [2] 45 8d [2] 5e 8b [2] 42 8c [2] 5e a3 }

  condition:
    any of them
}