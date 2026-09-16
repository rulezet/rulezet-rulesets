rule TTP_XOR_QUAD_CurrentVersionRun_c3be {
  strings:
    $key_c3be = { 90 d1 [2] b4 df [2] 9f f3 [2] b1 d1 [2] a5 ca [2] aa d0 [2] b4 cd [2] b6 cc [2] ad ca [2] b1 cd [2] ad e2 }

  condition:
    any of them
}