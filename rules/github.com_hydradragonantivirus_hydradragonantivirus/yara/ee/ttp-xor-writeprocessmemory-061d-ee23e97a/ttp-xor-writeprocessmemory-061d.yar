rule TTP_XOR_WriteProcessMemory_061d {
  strings:
    $key_061d = { 51 6f [2] 63 4d [2] 65 78 [2] 4b 78 [2] 74 64 }

  condition:
    any of them
}