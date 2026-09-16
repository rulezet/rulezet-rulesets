rule TTP_XOR_WriteProcessMemory_e91d {
  strings:
    $key_e91d = { be 6f [2] 8c 4d [2] 8a 78 [2] a4 78 [2] 9b 64 }

  condition:
    any of them
}