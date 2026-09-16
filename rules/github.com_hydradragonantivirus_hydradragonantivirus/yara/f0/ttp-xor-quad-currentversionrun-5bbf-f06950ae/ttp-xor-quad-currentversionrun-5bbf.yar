rule TTP_XOR_QUAD_CurrentVersionRun_5bbf {
  strings:
    $key_5bbf = { 08 d0 [2] 2c de [2] 07 f2 [2] 29 d0 [2] 3d cb [2] 32 d1 [2] 2c cc [2] 2e cd [2] 35 cb [2] 29 cc [2] 35 e3 }

  condition:
    any of them
}