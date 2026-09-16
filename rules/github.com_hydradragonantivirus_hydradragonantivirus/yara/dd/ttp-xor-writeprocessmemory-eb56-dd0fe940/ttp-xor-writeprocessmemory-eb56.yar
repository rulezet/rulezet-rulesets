rule TTP_XOR_WriteProcessMemory_eb56 {
  strings:
    $key_eb56 = { bc 24 [2] 8e 06 [2] 88 33 [2] a6 33 [2] 99 2f }

  condition:
    any of them
}