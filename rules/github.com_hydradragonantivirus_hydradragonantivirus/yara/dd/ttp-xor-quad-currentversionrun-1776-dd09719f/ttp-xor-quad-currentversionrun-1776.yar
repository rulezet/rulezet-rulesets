rule TTP_XOR_QUAD_CurrentVersionRun_1776 {
  strings:
    $key_1776 = { 44 19 [2] 60 17 [2] 4b 3b [2] 65 19 [2] 71 02 [2] 7e 18 [2] 60 05 [2] 62 04 [2] 79 02 [2] 65 05 [2] 79 2a }

  condition:
    any of them
}