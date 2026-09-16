rule TTP_XOR_QUAD_CurrentVersionRun_feb1 {
  strings:
    $key_feb1 = { ad de [2] 89 d0 [2] a2 fc [2] 8c de [2] 98 c5 [2] 97 df [2] 89 c2 [2] 8b c3 [2] 90 c5 [2] 8c c2 [2] 90 ed }

  condition:
    any of them
}