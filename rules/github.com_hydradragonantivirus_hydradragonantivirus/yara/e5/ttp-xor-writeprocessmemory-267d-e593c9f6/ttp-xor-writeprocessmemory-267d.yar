rule TTP_XOR_WriteProcessMemory_267d {
  strings:
    $key_267d = { 71 0f [2] 43 2d [2] 45 18 [2] 6b 18 [2] 54 04 }

  condition:
    any of them
}