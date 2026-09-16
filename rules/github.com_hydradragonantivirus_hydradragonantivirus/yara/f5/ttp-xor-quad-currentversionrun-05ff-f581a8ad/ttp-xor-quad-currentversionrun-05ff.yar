rule TTP_XOR_QUAD_CurrentVersionRun_05ff {
  strings:
    $key_05ff = { 56 90 [2] 72 9e [2] 59 b2 [2] 77 90 [2] 63 8b [2] 6c 91 [2] 72 8c [2] 70 8d [2] 6b 8b [2] 77 8c [2] 6b a3 }

  condition:
    any of them
}