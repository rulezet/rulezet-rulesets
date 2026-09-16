rule TTP_XOR_QUAD_CurrentVersionRun_695f {
  strings:
    $key_695f = { 3a 30 [2] 1e 3e [2] 35 12 [2] 1b 30 [2] 0f 2b [2] 00 31 [2] 1e 2c [2] 1c 2d [2] 07 2b [2] 1b 2c [2] 07 03 }

  condition:
    any of them
}