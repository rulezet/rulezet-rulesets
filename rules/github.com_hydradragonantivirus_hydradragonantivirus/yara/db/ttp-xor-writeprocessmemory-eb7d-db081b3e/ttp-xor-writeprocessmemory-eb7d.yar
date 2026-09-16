rule TTP_XOR_WriteProcessMemory_eb7d {
  strings:
    $key_eb7d = { bc 0f [2] 8e 2d [2] 88 18 [2] a6 18 [2] 99 04 }

  condition:
    any of them
}