rule TTP_XOR_WriteProcessMemory_5ebf {
  strings:
    $key_5ebf = { 09 cd [2] 3b ef [2] 3d da [2] 13 da [2] 2c c6 }

  condition:
    any of them
}