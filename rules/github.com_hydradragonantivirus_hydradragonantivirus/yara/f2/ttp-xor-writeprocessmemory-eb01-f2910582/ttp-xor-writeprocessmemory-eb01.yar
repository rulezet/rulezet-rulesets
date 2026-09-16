rule TTP_XOR_WriteProcessMemory_eb01 {
  strings:
    $key_eb01 = { bc 73 [2] 8e 51 [2] 88 64 [2] a6 64 [2] 99 78 }

  condition:
    any of them
}