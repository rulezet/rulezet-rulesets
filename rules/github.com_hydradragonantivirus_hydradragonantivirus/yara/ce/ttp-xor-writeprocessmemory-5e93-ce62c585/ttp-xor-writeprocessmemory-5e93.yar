rule TTP_XOR_WriteProcessMemory_5e93 {
  strings:
    $key_5e93 = { 09 e1 [2] 3b c3 [2] 3d f6 [2] 13 f6 [2] 2c ea }

  condition:
    any of them
}