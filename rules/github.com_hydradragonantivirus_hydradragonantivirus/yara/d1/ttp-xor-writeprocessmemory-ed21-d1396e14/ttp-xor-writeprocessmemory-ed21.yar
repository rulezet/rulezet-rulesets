rule TTP_XOR_WriteProcessMemory_ed21 {
  strings:
    $key_ed21 = { ba 53 [2] 88 71 [2] 8e 44 [2] a0 44 [2] 9f 58 }

  condition:
    any of them
}