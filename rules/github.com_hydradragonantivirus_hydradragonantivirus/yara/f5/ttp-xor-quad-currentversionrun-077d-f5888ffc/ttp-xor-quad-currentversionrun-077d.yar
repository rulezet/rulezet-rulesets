rule TTP_XOR_QUAD_CurrentVersionRun_077d {
  strings:
    $key_077d = { 54 12 [2] 70 1c [2] 5b 30 [2] 75 12 [2] 61 09 [2] 6e 13 [2] 70 0e [2] 72 0f [2] 69 09 [2] 75 0e [2] 69 21 }

  condition:
    any of them
}