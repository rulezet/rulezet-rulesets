rule TTP_XOR_QUAD_CurrentVersionRun_dbcd {
  strings:
    $key_dbcd = { 88 a2 [2] ac ac [2] 87 80 [2] a9 a2 [2] bd b9 [2] b2 a3 [2] ac be [2] ae bf [2] b5 b9 [2] a9 be [2] b5 91 }

  condition:
    any of them
}