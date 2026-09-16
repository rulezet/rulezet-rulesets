rule TTP_XOR_QUAD_CurrentVersionRun_ffcd {
  strings:
    $key_ffcd = { ac a2 [2] 88 ac [2] a3 80 [2] 8d a2 [2] 99 b9 [2] 96 a3 [2] 88 be [2] 8a bf [2] 91 b9 [2] 8d be [2] 91 91 }

  condition:
    any of them
}