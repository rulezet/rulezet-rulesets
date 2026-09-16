rule TTP_XOR_WriteProcessMemory_edcd {
  strings:
    $key_edcd = { ba bf [2] 88 9d [2] 8e a8 [2] a0 a8 [2] 9f b4 }

  condition:
    any of them
}