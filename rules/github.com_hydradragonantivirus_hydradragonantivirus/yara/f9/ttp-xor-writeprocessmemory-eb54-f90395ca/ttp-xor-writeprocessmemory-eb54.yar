rule TTP_XOR_WriteProcessMemory_eb54 {
  strings:
    $key_eb54 = { bc 26 [2] 8e 04 [2] 88 31 [2] a6 31 [2] 99 2d }

  condition:
    any of them
}